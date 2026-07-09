/*
 * deobf_analysis_core.hpp -- IDA-free deobfuscation classifiers.
 *
 * The IDA adapter translates decoded instructions and flow-chart blocks into
 * this deliberately small IR.  Keeping all semantic classifiers here makes
 * their boundary conditions testable without an IDB, Hex-Rays, or rax.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace viy {
namespace deobf {

constexpr uint64_t kBadAddress = ~uint64_t(0);
constexpr int32_t kNoRegister = -1;

enum class Architecture : uint8_t
{
  Unsupported = 0,
  X86,
  Arm32,
  Arm64,
};

enum class InstructionKind : uint8_t
{
  Other = 0,
  Nop,
  DirectCall,
  IndirectCall,
  DirectJump,
  IndirectJump,
  ConditionalBranch,
  Return,
  PopRegister,
  PushRegister,
  PushImmediate,
  ReadStackTop,
  AddStackTopImmediate,
  AdjustStackPointerImmediate,
  LoadImmediate,
  LoadAddress,
  LoadReadOnlyConstant,
  CopyRegister,
  AddImmediate,
  SubImmediate,
  XorImmediate,
  AndImmediate,
  OrImmediate,
  ShiftLeftImmediate,
  ReplaceHigh16,
  CompareImmediate,
  TestImmediate,
};

// Canonical x86 condition ordering pairs each predicate with its inverse by
// xor-one.  Unknown includes loop/jcxz-family branches, which do not consume
// the arithmetic flags modeled by this core.
enum class X86Condition : uint8_t
{
  Overflow = 0,
  NotOverflow,
  Carry,
  NotCarry,
  Zero,
  NotZero,
  BelowOrEqual,
  Above,
  Sign,
  NotSign,
  Parity,
  NotParity,
  Less,
  GreaterOrEqual,
  LessOrEqual,
  Greater,
  Unknown = 0xff,
};

enum class FlagEffect : uint8_t
{
  Preserve = 0,
  KnownCompare,
  KnownTest,
  UnknownWrite,
};

struct Instruction
{
  uint64_t address = kBadAddress;
  uint16_t size = 0;
  InstructionKind kind = InstructionKind::Other;
  int32_t destination_register = kNoRegister;
  int32_t source_register = kNoRegister;
  std::string destination_name;
  std::string source_name;
  uint8_t value_width = 0;          // bytes, 1..8 for modeled integers
  uint64_t immediate = 0;
  uint64_t target = kBadAddress;
  uint64_t memory_address = kBadAddress;
  X86Condition condition = X86Condition::Unknown;
  FlagEffect flag_effect = FlagEffect::UnknownWrite;
  bool register_is_left_operand = true; // CompareImmediate only

  // Set by the host adapter when another CFG edge enters this instruction.
  // Linear gadget/flag proofs stop at such joins.
  bool alternate_predecessor = false;
  bool writes_global_memory = false;
  bool plumbing = false;            // argument moves, stack setup, NOPs, etc.

  uint64_t end() const;
};

struct Block
{
  uint64_t start = kBadAddress;
  uint64_t end = kBadAddress;
  std::vector<uint64_t> successors;
  size_t predecessor_count = 0;
  std::vector<Instruction> instructions;
};

struct FunctionShape
{
  uint64_t entry = kBadAddress;
  uint64_t end = kBadAddress;
  std::vector<Instruction> instructions;
  size_t caller_count = 0;
  bool has_tail_chunks = false;
  bool already_special = false;     // library/thunk/hidden/outlined
  bool direct_callee_returns = true;
  bool scan_complete = true;
};

struct ClassifierLimits
{
  size_t gadget_depth = 12;
  uint64_t maximum_gap = 0x100;
  uint64_t entry_predicate_window = 0x40;
  size_t wrapper_maximum_instructions = 12;
  size_t wrapper_maximum_callers = 32; // 0 means unlimited
  size_t minimum_constant_steps = 2;
  size_t minimum_dispatch_cases = 3;
  size_t maximum_dispatch_cases = 256;
};

enum class GetPcMode : uint8_t
{
  PopReturnAddress = 0,
  ReadReturnAddress,
  AdjustReturnAddress,
  DiscardReturnAddress,
};

struct GetPcCandidate
{
  uint64_t call = kBadAddress;
  uint64_t gadget = kBadAddress;
  uint64_t pushed_return = kBadAddress;
  uint64_t return_instruction = kBadAddress;
  std::optional<uint64_t> resumed_at;
  int32_t pc_register = kNoRegister;
  std::string pc_register_name;
  std::optional<uint64_t> register_value_at_return;
  int64_t delta = 0;
  GetPcMode mode = GetPcMode::PopReturnAddress;
  std::vector<uint64_t> support;
};

// `other_callers` is supplied by the host because incoming-reference queries
// are deliberately outside the core.  The gadget vector must start at the
// direct call target and be in exact linear address order.
std::optional<GetPcCandidate> classify_get_pc_gadget(
    const Instruction &call,
    const std::vector<Instruction> &gadget,
    bool other_callers,
    const ClassifierLimits &limits = {});

struct GapCandidate
{
  uint64_t branch = kBadAddress;
  uint64_t start = kBadAddress;
  uint64_t end = kBadAddress;
};

// `gap_is_unreferenced` means the host verified every byte has no name,
// function entry, or inbound reference.  This still produces only a heuristic
// data-region candidate: dynamically-computed entries remain possible.
std::optional<GapCandidate> classify_jump_gap(
    const Instruction &branch,
    bool gap_is_loaded,
    bool gap_is_unreferenced,
    const ClassifierLimits &limits = {});

enum class PredicateKnowledge : uint8_t
{
  Unknown = 0,
  EntryFlagsUnspecified,
  ConstantOutcome,
};

struct EntryPredicateCandidate
{
  uint64_t branch = kBadAddress;
  uint64_t target = kBadAddress;
  uint64_t fallthrough = kBadAddress;
  PredicateKnowledge knowledge = PredicateKnowledge::Unknown;
  std::optional<bool> taken;
  std::vector<uint64_t> support;
};

// Classifies the first arithmetic-flag branch in the entry block.  A branch
// before any flag writer is an annotation candidate only: ABI entry flags are
// unspecified, so this never invents an unreachable edge.  A compare/test fed
// by an exact local constant yields an exact direction.
std::optional<EntryPredicateCandidate> classify_entry_predicate(
    uint64_t function_entry,
    const std::vector<Instruction> &entry_block,
    const ClassifierLimits &limits = {});

struct WrapperCandidate
{
  uint64_t function = kBadAddress;
  uint64_t target = kBadAddress;
  bool thunk = false;
  bool tail_call = false;
  size_t instruction_count = 0;
};

std::optional<WrapperCandidate> classify_wrapper(
    const FunctionShape &function,
    const ClassifierLimits &limits = {});

enum class ConstantTargetKind : uint8_t
{
  IndirectCall = 0,
  IndirectJump,
  PushReturn,
};

struct ConstantTargetCandidate
{
  uint64_t instruction = kBadAddress;
  uint64_t target = kBadAddress;
  ConstantTargetKind kind = ConstantTargetKind::IndirectJump;
  int32_t register_id = kNoRegister;
  std::string register_name;
  uint8_t value_width = 0;
  size_t transformation_steps = 0;
  bool used_read_only_load = false;
  std::vector<uint64_t> support;
};

struct ConstantAssignment
{
  uint64_t instruction = kBadAddress;
  int32_t register_id = kNoRegister;
  uint64_t value = 0;
  uint8_t value_width = 0;
  size_t transformation_steps = 0;
  std::vector<uint64_t> support;
};

struct ConstantBlockResult
{
  std::vector<ConstantTargetCandidate> targets;
  std::vector<ConstantAssignment> final_assignments;
};

// Constants never flow across blocks here.  The host may invoke this on every
// CFG block; joins therefore cannot silently manufacture a path-insensitive
// target.  Calls clear the register state.
ConstantBlockResult analyze_constant_block(
    const Block &block,
    const ClassifierLimits &limits = {});

struct DispatchCaseCandidate
{
  uint64_t selector = 0;
  uint64_t target = kBadAddress;
};

struct DispatchCandidate
{
  uint64_t entry_block = kBadAddress;
  uint64_t site = kBadAddress;
  int32_t state_register = kNoRegister;
  std::string state_register_name;
  uint8_t state_width = 0;
  std::vector<DispatchCaseCandidate> cases;
  std::optional<uint64_t> default_target;
  std::vector<uint64_t> comparison_sites;
  bool loop_backed = false;
  uint8_t selector_one_bit_percent = 0;
};

// Finds connected cmp/test-and-branch chains over one register.  Returned maps
// are intentionally incomplete candidates; proving switch completeness needs
// stronger semantics than a static IDA CFG provides.
std::vector<DispatchCandidate> find_dispatch_candidates(
    const std::vector<Block> &blocks,
    const ClassifierLimits &limits = {});

} // namespace deobf
} // namespace viy
