/*
 * analysis_facts.hpp -- producer-neutral analysis evidence for viy.
 *
 * This file deliberately has no IDA or rax dependencies.  Producers describe
 * what they learned as a typed FactPayload and attach one Evidence observation
 * carrying provenance, proof quality and run/function scope.  Keeping the
 * observation separate from the payload lets EvidenceStore coalesce the same
 * semantic fact across emulation runs and static-analysis producers without
 * losing provenance.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace viy {
namespace analysis {

using Address = uint64_t;

// Confidence is an integer probability-like score in basis points.  It is not
// automatically combined as if observations were statistically independent.
// EvidenceStore exposes max confidence and corroboration counts instead.
constexpr uint16_t kMaxConfidence = 10000;

enum class FactKind : uint8_t
{
  CodeTarget = 1,
  BranchReachability,
  MemoryAccess,
  MemoryValue,
  StringCandidate,
  FunctionCandidate,
  FunctionTrait,
  CodeRegion,
  DispatchMap,
  CfgCandidate,
  FunctionOutcome,
  RegisterValue,
  CallObservation,
};

enum class ProofKind : uint8_t
{
  Unknown = 0,
  Observed,
  StaticProof,
  SymbolicProof,
  CrossRunCorroboration,
  Heuristic,
  Imported,
  UserAsserted,
};

enum class CodeTargetKind : uint8_t
{
  Unknown = 0,
  Call,
  Jump,
  Fallthrough,
  Return,
  TableEntry,
  Exception,
};

enum class Reachability : uint8_t
{
  NotObserved = 0,       // absence only; never conflicts with reachability
  Reached,               // positively observed or proved reachable
  ProvenUnreachable,     // requires a proof; stronger than non-observation
};

enum class MemoryAccessKind : uint8_t
{
  Read = 1,
  Write,
  Execute,
  ReadWrite,
};

enum class StringEncoding : uint8_t
{
  Bytes = 0,
  Ascii,
  Utf8,
  Utf16LE,
  Utf16BE,
  Utf32LE,
  Utf32BE,
};

enum class FunctionCandidateKind : uint8_t
{
  Other = 0,
  EntryPoint,
  CallTarget,
  Prologue,
  OrphanChunk,
  ExceptionHandler,
  Export,
  UserAsserted,
};

enum class FunctionTraitKind : uint8_t
{
  Other = 0,
  Returns,
  NoReturn,
  StackDelta,
  ArgumentRegister,
  ReturnConstant,
  WrapperTarget,
  Leaf,
  Thunk,
  CallingConvention,
};

enum class TraitValueKind : uint8_t
{
  None = 0,
  Signed,
  Unsigned,
  Boolean,
  Text,
};

enum class CodeRegionKind : uint8_t
{
  Unknown = 0,
  Code,
  Data,
  Mixed,
  Padding,
};

enum class CfgEdgeKind : uint8_t
{
  Unknown = 0,
  Fallthrough,
  TrueBranch,
  FalseBranch,
  Call,
  Return,
  Exception,
  Indirect,
};

enum class FunctionStopKind : uint8_t
{
  Unknown = 0,
  Returned,
  Halted,
  Faulted,
  TimedOut,
  BudgetExhausted,
  EscapedFunction,
  TerminatedProcess,
};

enum class RegisterStatePoint : uint8_t
{
  BeforeInstruction = 1,
  AfterInstruction,
  FunctionEntry,
  FunctionExit,
  CallEntry,
  CallReturn,
};

enum class CallKind : uint8_t
{
  Unknown = 0,
  Call,
  TailCall,
  SystemCall,
  ImportedCall,
};

enum class CallResult : uint8_t
{
  Unknown = 0,
  Returned,
  NoReturn,
  Faulted,
  TimedOut,
};

// Scope fields are independently optional because a static producer may have a
// function scope but no run, while a whole-image trace may have a run and seed
// but no containing function.  function_end is exclusive when present.
struct EvidenceScope
{
  std::optional<uint64_t> run_id;
  std::optional<uint64_t> seed;
  std::optional<Address> function_start;
  std::optional<Address> function_end;
  uint64_t generation = 0;
};

struct Evidence
{
  std::string producer;             // stable producer id, e.g. "rax.emulator"
  std::string method;               // stable method/pass id
  ProofKind proof = ProofKind::Unknown;
  uint16_t confidence = 0;          // [0, kMaxConfidence]
  EvidenceScope scope;
  std::vector<Address> support_addresses;
  std::string detail;               // optional human-readable proof note
};

struct CodeTargetFact
{
  Address from = 0;
  Address target = 0;
  CodeTargetKind kind = CodeTargetKind::Unknown;
  // True means this observation asserts that `target` is the sole target for
  // (from, kind), allowing conflicting sole-target assertions to be detected.
  bool unique = false;
};

struct BranchReachabilityFact
{
  Address branch = 0;
  Address successor = 0;
  Reachability state = Reachability::NotObserved;
};

struct MemoryAccessFact
{
  Address instruction = 0;
  Address address = 0;
  uint32_t size = 0;
  MemoryAccessKind kind = MemoryAccessKind::Read;
};

struct MemoryValueFact
{
  Address instruction = 0;
  Address address = 0;
  MemoryAccessKind kind = MemoryAccessKind::Read;
  // Bytes are in increasing memory-address order, independent of target
  // endianness.  This avoids truncation and endian ambiguity.
  std::vector<uint8_t> bytes;
};

struct StringCandidateFact
{
  Address address = 0;
  StringEncoding encoding = StringEncoding::Bytes;
  std::vector<uint8_t> bytes;       // exact candidate bytes, terminator excluded
  std::string decoded;              // UTF-8 display form; may be empty
  bool null_terminated = false;
};

struct FunctionCandidateFact
{
  Address entry = 0;
  std::optional<Address> end;       // exclusive when known
  FunctionCandidateKind kind = FunctionCandidateKind::Other;
};

struct TraitValue
{
  TraitValueKind kind = TraitValueKind::None;
  int64_t signed_value = 0;
  uint64_t unsigned_value = 0;
  bool boolean_value = false;
  std::string text_value;

  static TraitValue none();
  static TraitValue signed_integer(int64_t value);
  static TraitValue unsigned_integer(uint64_t value);
  static TraitValue boolean(bool value);
  static TraitValue text(std::string value);
};

struct FunctionTraitFact
{
  Address function = 0;
  FunctionTraitKind trait = FunctionTraitKind::Other;
  // Returns/NoReturn/Leaf/Thunk use None; StackDelta uses Signed;
  // ArgumentRegister uses Unsigned or Text; ReturnConstant uses Signed or
  // Unsigned; WrapperTarget uses Unsigned; CallingConvention uses Text.  Other
  // is the extensibility escape hatch and accepts any TraitValue kind.
  TraitValue value;
};

struct CodeRegionFact
{
  Address start = 0;
  Address end = 0;                  // exclusive
  CodeRegionKind kind = CodeRegionKind::Unknown;
};

struct DispatchCase
{
  // Missing selector means an observed target whose case value is unknown.
  std::optional<uint64_t> selector;
  Address target = 0;
};

struct DispatchMapFact
{
  Address site = 0;
  std::vector<DispatchCase> cases;
  std::optional<Address> default_target;
  // Complete is an assertion that all possible dispatch destinations are in
  // cases/default_target; incomplete observed subsets are never treated as an
  // exhaustive switch reconstruction.
  bool complete = false;
};

struct CfgCandidateFact
{
  Address from = 0;
  Address to = 0;
  CfgEdgeKind kind = CfgEdgeKind::Unknown;
  Reachability state = Reachability::NotObserved;
};

struct FunctionOutcomeFact
{
  Address function = 0;
  FunctionStopKind stop = FunctionStopKind::Unknown;
  std::optional<Address> stop_pc;
  std::optional<int64_t> stack_delta;
  std::optional<uint64_t> instruction_count;
};

// A producer-neutral value for one architectural register at a precise state
// point.  register_id is a stable architecture spelling (for example "rax",
// "x0", or "riscv:x10").  Bytes are least-significant first, independent of
// the analyzed program's endianness, and retain values wider than 64 bits.
struct RegisterValueFact
{
  Address instruction = 0;
  RegisterStatePoint point = RegisterStatePoint::BeforeInstruction;
  std::string register_id;
  std::vector<uint8_t> bytes;
};

// One known argument or return component.  `ordinal` identifies the logical
// argument/return; `location` identifies its ABI carrier using an extensible
// producer-neutral spelling such as "reg:x0" or "stack:+0x8".  Multiple
// locations may represent components of one aggregate ordinal.
struct CallValue
{
  uint32_t ordinal = 0;
  std::string location;
  std::vector<uint8_t> bytes;       // least-significant byte first
};

struct CallObservationFact
{
  Address source = 0;               // calling instruction
  std::optional<Address> target;    // absent while still unresolved
  CallKind kind = CallKind::Unknown;
  CallResult result = CallResult::Unknown;
  std::vector<CallValue> arguments;
  std::vector<CallValue> returns;
};

using FactPayload = std::variant<CodeTargetFact,
                                 BranchReachabilityFact,
                                 MemoryAccessFact,
                                 MemoryValueFact,
                                 StringCandidateFact,
                                 FunctionCandidateFact,
                                 FunctionTraitFact,
                                 CodeRegionFact,
                                 DispatchMapFact,
                                 CfgCandidateFact,
                                 FunctionOutcomeFact,
                                 RegisterValueFact,
                                 CallObservationFact>;

struct AnalysisFact
{
  FactPayload payload;
  Evidence evidence;
};

// SHA-256 over the versioned canonical encoding.  Unlike std::hash this is
// stable across processes, standard-library implementations and architectures.
struct FactDigest
{
  std::array<uint8_t, 32> bytes{};

  std::string hex() const;
};

bool operator==(const FactDigest &lhs, const FactDigest &rhs);
bool operator!=(const FactDigest &lhs, const FactDigest &rhs);
bool operator<(const FactDigest &lhs, const FactDigest &rhs);

struct FactCodecLimits
{
  size_t max_fact_bytes = 4u * 1024u * 1024u;
  size_t max_string_bytes = 1u * 1024u * 1024u;
  size_t max_vector_items = 1u * 1024u * 1024u;
};

FactKind fact_kind(const FactPayload &payload);
const char *fact_kind_name(FactKind kind);

// Normalization sorts/deduplicates set-like vectors and clears inactive
// TraitValue fields.  Validation rejects malformed ranges, enum values,
// impossible scopes and oversized/empty values.  The two operations are kept
// explicit so callers can report bad producer output instead of silently
// storing it.
bool normalize_payload(FactPayload &payload, std::string *error = nullptr);
bool normalize_evidence(Evidence &evidence, std::string *error = nullptr);
bool normalize_fact(AnalysisFact &fact, std::string *error = nullptr);
bool validate_payload(const FactPayload &payload, std::string *error = nullptr);
bool validate_evidence(const Evidence &evidence, std::string *error = nullptr);
bool validate_fact(const AnalysisFact &fact, std::string *error = nullptr);

// Canonical encodings are versioned, endian-independent and deterministic.
// The payload encoding intentionally excludes Evidence so it can be used as a
// semantic deduplication key.  Decoders require the complete input to be
// consumed and leave `out` untouched on failure.
bool encode_payload(const FactPayload &payload,
                    std::vector<uint8_t> &out,
                    std::string *error = nullptr);
bool decode_payload(const std::vector<uint8_t> &bytes,
                    FactPayload &out,
                    std::string *error = nullptr,
                    const FactCodecLimits &limits = {});
bool encode_evidence(const Evidence &evidence,
                     std::vector<uint8_t> &out,
                     std::string *error = nullptr);
bool decode_evidence(const std::vector<uint8_t> &bytes,
                     Evidence &out,
                     std::string *error = nullptr,
                     const FactCodecLimits &limits = {});
bool encode_analysis_fact(const AnalysisFact &fact,
                          std::vector<uint8_t> &out,
                          std::string *error = nullptr);
bool decode_analysis_fact(const std::vector<uint8_t> &bytes,
                          AnalysisFact &out,
                          std::string *error = nullptr,
                          const FactCodecLimits &limits = {});

bool stable_digest(const FactPayload &payload,
                   FactDigest &out,
                   std::string *error = nullptr);
bool stable_digest(const Evidence &evidence,
                   FactDigest &out,
                   std::string *error = nullptr);
bool stable_digest(const AnalysisFact &fact,
                   FactDigest &out,
                   std::string *error = nullptr);
// Raw SHA-256 helper used by the versioned store envelope.  Semantic fact
// identities should use the overloads above, which include codec/domain tags.
FactDigest sha256_bytes(const std::vector<uint8_t> &bytes);

// Canonical comparisons normalize copies before comparing.  Invalid inputs
// sort after valid ones, with their validation message providing a stable
// fallback order; EvidenceStore itself rejects invalid inputs.
bool payload_less(const FactPayload &lhs, const FactPayload &rhs);
bool evidence_less(const Evidence &lhs, const Evidence &rhs);
bool analysis_fact_less(const AnalysisFact &lhs, const AnalysisFact &rhs);
bool payload_equal(const FactPayload &lhs, const FactPayload &rhs);
bool evidence_equal(const Evidence &lhs, const Evidence &rhs);

} // namespace analysis
} // namespace viy
