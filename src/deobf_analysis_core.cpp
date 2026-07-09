#include "deobf_analysis_core.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace viy {
namespace deobf {
namespace {

uint64_t width_mask(uint8_t width)
{
  if ( width == 0 || width > 8 )
    return 0;
  return width == 8 ? std::numeric_limits<uint64_t>::max()
                    : (uint64_t(1) << (unsigned(width) * 8u)) - 1u;
}

uint64_t truncate_width(uint64_t value, uint8_t width)
{
  return value & width_mask(width);
}

bool add_signed_address(uint64_t base, int64_t delta, uint64_t *out)
{
  if ( out == nullptr )
    return false;
  if ( delta >= 0 )
  {
    const uint64_t add = static_cast<uint64_t>(delta);
    if ( base > std::numeric_limits<uint64_t>::max() - add )
      return false;
    *out = base + add;
    return true;
  }
  // Avoid negating INT64_MIN in the signed domain.
  const uint64_t sub = uint64_t(-(delta + 1)) + 1u;
  if ( base < sub )
    return false;
  *out = base - sub;
  return true;
}

bool add_delta(int64_t *value, int64_t delta)
{
  if ( value == nullptr )
    return false;
  if ( delta > 0 && *value > std::numeric_limits<int64_t>::max() - delta )
    return false;
  if ( delta < 0 && *value < std::numeric_limits<int64_t>::min() - delta )
    return false;
  *value += delta;
  return true;
}

void normalize_support(std::vector<uint64_t> &support)
{
  support.erase(std::remove(support.begin(), support.end(), kBadAddress),
                support.end());
  std::sort(support.begin(), support.end());
  support.erase(std::unique(support.begin(), support.end()), support.end());
}

struct ConstantState
{
  uint64_t value = 0;
  uint8_t width = 0;
  size_t steps = 0;
  bool read_only_load = false;
  std::vector<uint64_t> support;
};

using StateMap = std::unordered_map<int32_t, ConstantState>;

void erase_destination(StateMap &state, const Instruction &insn)
{
  if ( insn.destination_register != kNoRegister )
    state.erase(insn.destination_register);
}

bool valid_integer_instruction(const Instruction &insn)
{
  return insn.destination_register != kNoRegister
      && insn.value_width >= 1 && insn.value_width <= 8;
}

void assign_constant(StateMap &state, const Instruction &insn,
                     uint64_t value, size_t steps, bool read_only,
                     std::vector<uint64_t> support)
{
  if ( !valid_integer_instruction(insn) )
  {
    erase_destination(state, insn);
    return;
  }
  support.push_back(insn.address);
  normalize_support(support);
  state[insn.destination_register] = ConstantState{
      truncate_width(value, insn.value_width), insn.value_width, steps,
      read_only, std::move(support) };
}

// Applies only register-value semantics.  Flag semantics are deliberately
// handled by classify_entry_predicate so a compare cannot alter the constants.
void update_constants(StateMap &state, const Instruction &insn)
{
  switch ( insn.kind )
  {
    case InstructionKind::LoadImmediate:
    case InstructionKind::LoadAddress:
      assign_constant(state, insn, insn.immediate, 1, false, {});
      return;

    case InstructionKind::LoadReadOnlyConstant:
      assign_constant(state, insn, insn.immediate, 1, true,
                      { insn.memory_address });
      return;

    case InstructionKind::CopyRegister:
    {
      const auto source = state.find(insn.source_register);
      if ( source == state.end() || !valid_integer_instruction(insn) )
      {
        erase_destination(state, insn);
        return;
      }
      ConstantState next = source->second;
      next.width = insn.value_width;
      next.value = truncate_width(next.value, next.width);
      ++next.steps;
      next.support.push_back(insn.address);
      normalize_support(next.support);
      state[insn.destination_register] = std::move(next);
      return;
    }

    case InstructionKind::AddImmediate:
    case InstructionKind::SubImmediate:
    case InstructionKind::XorImmediate:
    case InstructionKind::AndImmediate:
    case InstructionKind::OrImmediate:
    case InstructionKind::ShiftLeftImmediate:
    case InstructionKind::ReplaceHigh16:
    {
      const int32_t base_register = insn.source_register != kNoRegister
                                  ? insn.source_register
                                  : insn.destination_register;
      const auto base = state.find(base_register);
      if ( base == state.end() || !valid_integer_instruction(insn)
        || base->second.width != insn.value_width )
      {
        erase_destination(state, insn);
        return;
      }
      ConstantState next = base->second;
      const uint64_t mask = width_mask(insn.value_width);
      uint64_t value = next.value;
      switch ( insn.kind )
      {
        case InstructionKind::AddImmediate:
          value = (value + insn.immediate) & mask;
          break;
        case InstructionKind::SubImmediate:
          value = (value - insn.immediate) & mask;
          break;
        case InstructionKind::XorImmediate:
          value = (value ^ insn.immediate) & mask;
          break;
        case InstructionKind::AndImmediate:
          value = (value & insn.immediate) & mask;
          break;
        case InstructionKind::OrImmediate:
          value = (value | insn.immediate) & mask;
          break;
        case InstructionKind::ShiftLeftImmediate:
        {
          const unsigned bits = unsigned(insn.value_width) * 8u;
          if ( insn.immediate >= bits )
          {
            erase_destination(state, insn);
            return;
          }
          value = (value << unsigned(insn.immediate)) & mask;
          break;
        }
        case InstructionKind::ReplaceHigh16:
          if ( insn.value_width < 4 )
          {
            erase_destination(state, insn);
            return;
          }
          value = (value & UINT64_C(0x0000ffff))
                | ((insn.immediate & UINT64_C(0xffff)) << 16);
          value &= mask;
          break;
        default:
          break;
      }
      next.value = value;
      ++next.steps;
      next.support.push_back(insn.address);
      normalize_support(next.support);
      state[insn.destination_register] = std::move(next);
      return;
    }

    case InstructionKind::DirectCall:
    case InstructionKind::IndirectCall:
      state.clear();
      return;

    case InstructionKind::Other:
      // The core deliberately has no architecture-specific alias graph (e.g.
      // AH/EAX/RAX).  An unsupported register write therefore kills the whole
      // local state rather than preserving a stale value through an alias.
      if ( insn.destination_register != kNoRegister )
        state.clear();
      return;

    default:
      return;
  }
}

struct ArithmeticFlags
{
  bool carry = false;
  bool zero = false;
  bool sign = false;
  bool overflow = false;
  bool parity = false;
};

bool even_parity(uint8_t value)
{
  unsigned ones = 0;
  for ( unsigned i = 0; i < 8; ++i )
    ones += (value >> i) & 1u;
  return (ones & 1u) == 0;
}

std::optional<ArithmeticFlags> compare_flags(
    uint64_t lhs, uint64_t rhs, uint8_t width)
{
  const uint64_t mask = width_mask(width);
  if ( mask == 0 )
    return std::nullopt;
  lhs &= mask;
  rhs &= mask;
  const uint64_t result = (lhs - rhs) & mask;
  const uint64_t sign_bit = uint64_t(1) << (unsigned(width) * 8u - 1u);
  ArithmeticFlags flags;
  flags.carry = lhs < rhs;
  flags.zero = result == 0;
  flags.sign = (result & sign_bit) != 0;
  flags.overflow = ((lhs ^ rhs) & (lhs ^ result) & sign_bit) != 0;
  flags.parity = even_parity(static_cast<uint8_t>(result));
  return flags;
}

std::optional<ArithmeticFlags> test_flags(
    uint64_t lhs, uint64_t rhs, uint8_t width)
{
  const uint64_t mask = width_mask(width);
  if ( mask == 0 )
    return std::nullopt;
  const uint64_t result = (lhs & rhs) & mask;
  const uint64_t sign_bit = uint64_t(1) << (unsigned(width) * 8u - 1u);
  ArithmeticFlags flags;
  flags.carry = false;
  flags.zero = result == 0;
  flags.sign = (result & sign_bit) != 0;
  flags.overflow = false;
  flags.parity = even_parity(static_cast<uint8_t>(result));
  return flags;
}

std::optional<bool> evaluate_condition(
    X86Condition condition, const ArithmeticFlags &f)
{
  switch ( condition )
  {
    case X86Condition::Overflow:       return f.overflow;
    case X86Condition::NotOverflow:    return !f.overflow;
    case X86Condition::Carry:          return f.carry;
    case X86Condition::NotCarry:       return !f.carry;
    case X86Condition::Zero:           return f.zero;
    case X86Condition::NotZero:        return !f.zero;
    case X86Condition::BelowOrEqual:   return f.carry || f.zero;
    case X86Condition::Above:          return !f.carry && !f.zero;
    case X86Condition::Sign:           return f.sign;
    case X86Condition::NotSign:        return !f.sign;
    case X86Condition::Parity:         return f.parity;
    case X86Condition::NotParity:      return !f.parity;
    case X86Condition::Less:           return f.sign != f.overflow;
    case X86Condition::GreaterOrEqual: return f.sign == f.overflow;
    case X86Condition::LessOrEqual:    return f.zero || f.sign != f.overflow;
    case X86Condition::Greater:        return !f.zero && f.sign == f.overflow;
    case X86Condition::Unknown:        return std::nullopt;
  }
  return std::nullopt;
}

struct DispatchNode
{
  uint64_t block = kBadAddress;
  uint64_t site = kBadAddress;
  int32_t reg = kNoRegister;
  std::string reg_name;
  uint8_t width = 0;
  uint64_t selector = 0;
  uint64_t case_target = kBadAddress;
  uint64_t next = kBadAddress;
};

bool writes_destination_value(const Instruction &insn)
{
  if ( insn.destination_register == kNoRegister )
    return false;
  switch ( insn.kind )
  {
    case InstructionKind::PopRegister:
    case InstructionKind::ReadStackTop:
    case InstructionKind::LoadImmediate:
    case InstructionKind::LoadAddress:
    case InstructionKind::LoadReadOnlyConstant:
    case InstructionKind::CopyRegister:
    case InstructionKind::AddImmediate:
    case InstructionKind::SubImmediate:
    case InstructionKind::XorImmediate:
    case InstructionKind::AndImmediate:
    case InstructionKind::OrImmediate:
    case InstructionKind::ShiftLeftImmediate:
    case InstructionKind::ReplaceHigh16:
    case InstructionKind::Other:
      return true;
    default:
      return false;
  }
}

std::optional<DispatchNode> parse_dispatch_node(const Block &block)
{
  if ( block.instructions.size() < 2 )
    return std::nullopt;
  const Instruction &branch = block.instructions.back();
  if ( branch.kind != InstructionKind::ConditionalBranch
    || branch.target == kBadAddress
    || (branch.condition != X86Condition::Zero
     && branch.condition != X86Condition::NotZero) )
  {
    return std::nullopt;
  }
  const uint64_t fallthrough = branch.end();
  if ( fallthrough == kBadAddress )
    return std::nullopt;

  const Instruction *compare = nullptr;
  for ( auto it = block.instructions.rbegin() + 1;
        it != block.instructions.rend(); ++it )
  {
    if ( it->kind == InstructionKind::CompareImmediate )
    {
      compare = &*it;
      break;
    }
    if ( it->flag_effect == FlagEffect::UnknownWrite )
      return std::nullopt;
  }
  if ( compare == nullptr || compare->destination_register == kNoRegister
    || !compare->register_is_left_operand
    || compare->value_width == 0 || compare->value_width > 8 )
  {
    return std::nullopt;
  }
  for ( const Instruction &insn : block.instructions )
  {
    if ( &insn == compare || &insn == &branch )
      continue;
    if ( insn.destination_register == compare->destination_register
      && writes_destination_value(insn) )
    {
      return std::nullopt;
    }
  }

  const auto has_successor = [&](uint64_t value)
  {
    return std::find(block.successors.begin(), block.successors.end(), value)
        != block.successors.end();
  };
  if ( !has_successor(branch.target) || !has_successor(fallthrough) )
    return std::nullopt;

  DispatchNode node;
  node.block = block.start;
  node.site = branch.address;
  node.reg = compare->destination_register;
  node.reg_name = compare->destination_name;
  node.width = compare->value_width;
  node.selector = truncate_width(compare->immediate, compare->value_width);
  if ( branch.condition == X86Condition::Zero )
  {
    node.case_target = branch.target;
    node.next = fallthrough;
  }
  else
  {
    node.case_target = fallthrough;
    node.next = branch.target;
  }
  return node;
}

uint8_t selector_entropy(const std::vector<DispatchNode> &nodes)
{
  uint64_t total = 0;
  uint64_t ones = 0;
  for ( const DispatchNode &node : nodes )
  {
    const unsigned bits = unsigned(node.width) * 8u;
    total += bits;
    for ( unsigned bit = 0; bit < bits; ++bit )
      ones += (node.selector >> bit) & 1u;
  }
  return total == 0 ? 0 : static_cast<uint8_t>((ones * 100u) / total);
}

} // anonymous namespace

uint64_t Instruction::end() const
{
  if ( address == kBadAddress
    || address > std::numeric_limits<uint64_t>::max() - size )
  {
    return kBadAddress;
  }
  return address + size;
}

std::optional<GetPcCandidate> classify_get_pc_gadget(
    const Instruction &call,
    const std::vector<Instruction> &gadget,
    bool other_callers,
    const ClassifierLimits &limits)
{
  if ( call.kind != InstructionKind::DirectCall || call.size == 0
    || call.target == kBadAddress || gadget.empty() || other_callers
    || gadget.front().address != call.target || limits.gadget_depth == 0 )
  {
    return std::nullopt;
  }
  const uint64_t pushed_return = call.end();
  if ( pushed_return == kBadAddress || call.target == pushed_return )
    return std::nullopt; // ordinary call-$+instruction is handled by IDA
  if ( call.target > pushed_return
    && call.target - pushed_return > limits.maximum_gap )
  {
    return std::nullopt;
  }

  GetPcCandidate result;
  result.call = call.address;
  result.gadget = call.target;
  result.pushed_return = pushed_return;
  result.support = { call.address, call.target };

  const Instruction &entry = gadget.front();
  bool stack_target_adjusted = false;
  bool pushed_tracked_register = false;
  int64_t pushed_register_delta = 0;
  bool register_known = false;
  uint8_t pc_register_width = 0;
  switch ( entry.kind )
  {
    case InstructionKind::PopRegister:
      if ( entry.destination_register == kNoRegister )
        return std::nullopt;
      result.mode = GetPcMode::PopReturnAddress;
      result.pc_register = entry.destination_register;
      result.pc_register_name = entry.destination_name;
      pc_register_width = entry.value_width;
      register_known = true;
      break;
    case InstructionKind::ReadStackTop:
      if ( entry.destination_register == kNoRegister )
        return std::nullopt;
      result.mode = GetPcMode::ReadReturnAddress;
      result.pc_register = entry.destination_register;
      result.pc_register_name = entry.destination_name;
      pc_register_width = entry.value_width;
      register_known = true;
      break;
    case InstructionKind::AddStackTopImmediate:
      result.mode = GetPcMode::AdjustReturnAddress;
      result.delta = static_cast<int64_t>(entry.immediate);
      stack_target_adjusted = true;
      break;
    case InstructionKind::AdjustStackPointerImmediate:
      if ( static_cast<int64_t>(entry.immediate) <= 0 )
        return std::nullopt;
      result.mode = GetPcMode::DiscardReturnAddress;
      break;
    default:
      return std::nullopt;
  }

  uint64_t expected = entry.end();
  if ( expected == kBadAddress )
    return std::nullopt;
  const size_t count = std::min(gadget.size(), limits.gadget_depth + 1u);
  for ( size_t i = 1; i < count; ++i )
  {
    const Instruction &insn = gadget[i];
    if ( insn.address != expected || insn.alternate_predecessor )
      return std::nullopt;
    expected = insn.end();
    if ( expected == kBadAddress )
      return std::nullopt;
    result.support.push_back(insn.address);

    if ( insn.kind == InstructionKind::Return )
    {
      result.return_instruction = insn.address;
      if ( stack_target_adjusted || pushed_tracked_register )
      {
        uint64_t resumed = 0;
        const int64_t return_delta = pushed_tracked_register
                                   ? pushed_register_delta : result.delta;
        if ( !add_signed_address(pushed_return, return_delta, &resumed) )
          return std::nullopt;
        result.resumed_at = resumed;
      }
      if ( register_known )
      {
        uint64_t value = 0;
        if ( !add_signed_address(pushed_return, result.delta, &value) )
          return std::nullopt;
        result.register_value_at_return = value;
      }

      // Reading [sp] followed by an ordinary ret is a conventional helper,
      // not an obfuscated call+pop/push-ret construction.
      if ( result.mode == GetPcMode::ReadReturnAddress
        && !pushed_tracked_register )
      {
        return std::nullopt;
      }
      normalize_support(result.support);
      return result;
    }

    if ( insn.kind == InstructionKind::DirectCall
      || insn.kind == InstructionKind::IndirectCall
      || insn.kind == InstructionKind::DirectJump
      || insn.kind == InstructionKind::IndirectJump
      || insn.kind == InstructionKind::ConditionalBranch )
    {
      return std::nullopt;
    }

    if ( insn.kind == InstructionKind::PushImmediate
      || insn.kind == InstructionKind::PopRegister
      || insn.kind == InstructionKind::AddStackTopImmediate
      || insn.kind == InstructionKind::AdjustStackPointerImmediate )
    {
      return std::nullopt; // unmodeled change to the return-stack top
    }

    if ( register_known && insn.destination_register == result.pc_register )
    {
      if ( pc_register_width != 0 && insn.value_width != 0
        && insn.value_width != pc_register_width )
      {
        register_known = false;
      }
      int64_t adjustment = 0;
      if ( register_known && insn.kind == InstructionKind::AddImmediate )
        adjustment = static_cast<int64_t>(insn.immediate);
      else if ( register_known && insn.kind == InstructionKind::SubImmediate )
      {
        const int64_t value = static_cast<int64_t>(insn.immediate);
        if ( value == std::numeric_limits<int64_t>::min() )
          return std::nullopt;
        adjustment = -value;
      }
      else
      {
        register_known = false;
      }
      if ( register_known && !add_delta(&result.delta, adjustment) )
        return std::nullopt;
    }
    if ( insn.kind == InstructionKind::PushRegister
      && register_known && insn.source_register == result.pc_register
      && (pc_register_width == 0 || insn.value_width == 0
       || insn.value_width == pc_register_width) )
    {
      pushed_tracked_register = true;
      pushed_register_delta = result.delta;
    }
    else if ( insn.kind == InstructionKind::PushRegister )
    {
      return std::nullopt;
    }
  }

  if ( result.mode == GetPcMode::DiscardReturnAddress )
  {
    normalize_support(result.support);
    return result;
  }
  return std::nullopt;
}

std::optional<GapCandidate> classify_jump_gap(
    const Instruction &branch,
    bool gap_is_loaded,
    bool gap_is_unreferenced,
    const ClassifierLimits &limits)
{
  if ( branch.kind != InstructionKind::DirectJump || branch.size == 0
    || branch.target == kBadAddress || !gap_is_loaded
    || !gap_is_unreferenced )
  {
    return std::nullopt;
  }
  const uint64_t start = branch.end();
  if ( start == kBadAddress || branch.target <= start )
    return std::nullopt;
  if ( branch.target - start > limits.maximum_gap )
    return std::nullopt;
  return GapCandidate{ branch.address, start, branch.target };
}

std::optional<EntryPredicateCandidate> classify_entry_predicate(
    uint64_t function_entry,
    const std::vector<Instruction> &entry_block,
    const ClassifierLimits &limits)
{
  if ( function_entry == kBadAddress )
    return std::nullopt;
  StateMap constants;
  std::optional<ArithmeticFlags> known_flags;
  bool saw_flag_writer = false;
  uint64_t previous_end = function_entry;
  std::vector<uint64_t> flag_support;

  for ( size_t i = 0; i < entry_block.size(); ++i )
  {
    const Instruction &insn = entry_block[i];
    if ( insn.address < function_entry
      || insn.address - function_entry > limits.entry_predicate_window )
    {
      break;
    }
    if ( i != 0 && (insn.address != previous_end || insn.alternate_predecessor) )
      break;
    previous_end = insn.end();
    if ( previous_end == kBadAddress )
      break;

    if ( insn.kind == InstructionKind::ConditionalBranch
      && insn.condition != X86Condition::Unknown
      && insn.target != kBadAddress )
    {
      EntryPredicateCandidate result;
      result.branch = insn.address;
      result.target = insn.target;
      result.fallthrough = insn.end();
      if ( known_flags.has_value() )
      {
        const std::optional<bool> taken =
            evaluate_condition(insn.condition, *known_flags);
        if ( !taken.has_value() )
          return std::nullopt;
        result.knowledge = PredicateKnowledge::ConstantOutcome;
        result.taken = *taken;
        result.support = flag_support;
        result.support.push_back(insn.address);
        normalize_support(result.support);
        return result;
      }
      if ( !saw_flag_writer )
      {
        result.knowledge = PredicateKnowledge::EntryFlagsUnspecified;
        result.support = { function_entry, insn.address };
        normalize_support(result.support);
        return result;
      }
      return std::nullopt;
    }

    if ( insn.kind == InstructionKind::DirectCall
      || insn.kind == InstructionKind::IndirectCall )
    {
      // ABI callees may clobber arithmetic flags even though the CALL opcode
      // itself does not.  Never carry an exact predicate state across a call.
      saw_flag_writer = true;
      known_flags.reset();
      flag_support.clear();
    }
    else if ( insn.flag_effect == FlagEffect::KnownCompare
      || insn.flag_effect == FlagEffect::KnownTest )
    {
      saw_flag_writer = true;
      known_flags.reset();
      const auto value = constants.find(insn.destination_register);
      if ( value != constants.end()
        && value->second.width == insn.value_width )
      {
        const uint64_t reg_value = value->second.value;
        if ( insn.flag_effect == FlagEffect::KnownTest )
        {
          known_flags = test_flags(reg_value, insn.immediate,
                                   insn.value_width);
        }
        else if ( insn.register_is_left_operand )
        {
          known_flags = compare_flags(reg_value, insn.immediate,
                                      insn.value_width);
        }
        else
        {
          known_flags = compare_flags(insn.immediate, reg_value,
                                      insn.value_width);
        }
        if ( known_flags.has_value() )
        {
          flag_support = value->second.support;
          flag_support.push_back(insn.address);
        }
      }
    }
    else if ( insn.flag_effect == FlagEffect::UnknownWrite )
    {
      saw_flag_writer = true;
      known_flags.reset();
      flag_support.clear();
    }
    update_constants(constants, insn);
  }
  return std::nullopt;
}

std::optional<WrapperCandidate> classify_wrapper(
    const FunctionShape &function,
    const ClassifierLimits &limits)
{
  if ( function.entry == kBadAddress || function.already_special
    || function.has_tail_chunks || !function.scan_complete
    || function.instructions.empty()
    || function.instructions.size() > limits.wrapper_maximum_instructions
    || (limits.wrapper_maximum_callers != 0
     && function.caller_count > limits.wrapper_maximum_callers) )
  {
    return std::nullopt;
  }

  size_t calls = 0;
  size_t returns = 0;
  size_t jumps = 0;
  size_t conditional = 0;
  bool all_plumbing = true;
  uint64_t target = kBadAddress;
  for ( const Instruction &insn : function.instructions )
  {
    if ( insn.writes_global_memory )
      return std::nullopt;
    switch ( insn.kind )
    {
      case InstructionKind::DirectCall:
        ++calls;
        target = insn.target;
        break;
      case InstructionKind::IndirectCall:
      case InstructionKind::IndirectJump:
        return std::nullopt;
      case InstructionKind::DirectJump:
        ++jumps;
        target = insn.target;
        break;
      case InstructionKind::ConditionalBranch:
        ++conditional;
        break;
      case InstructionKind::Return:
        ++returns;
        break;
      default:
        if ( !insn.plumbing )
          all_plumbing = false;
        break;
    }
  }
  if ( target == kBadAddress || conditional != 0 )
    return std::nullopt;

  WrapperCandidate result;
  result.function = function.entry;
  result.target = target;
  result.instruction_count = function.instructions.size();
  if ( calls == 0 && jumps == 1 && returns == 0 )
  {
    result.thunk = all_plumbing;
    result.tail_call = true;
    return result;
  }
  if ( calls != 1 || jumps != 0 )
    return std::nullopt;
  if ( returns == 0 )
  {
    if ( function.direct_callee_returns )
      return std::nullopt;
  }
  else if ( returns != 1 )
  {
    return std::nullopt;
  }
  result.thunk = all_plumbing;
  return result;
}

ConstantBlockResult analyze_constant_block(
    const Block &block,
    const ClassifierLimits &limits)
{
  ConstantBlockResult result;
  StateMap state;
  std::optional<std::pair<int32_t, ConstantState>> pending_push;
  uint64_t expected = block.start;

  for ( const Instruction &insn : block.instructions )
  {
    if ( insn.address != expected || insn.alternate_predecessor )
    {
      state.clear();
      pending_push.reset();
    }
    expected = insn.end();
    if ( expected == kBadAddress )
      break;

    if ( insn.kind == InstructionKind::IndirectCall
      || insn.kind == InstructionKind::IndirectJump )
    {
      const int32_t reg = insn.source_register != kNoRegister
                        ? insn.source_register : insn.destination_register;
      const auto value = state.find(reg);
      if ( value != state.end()
        && (insn.value_width == 0
         || value->second.width == insn.value_width)
        && value->second.steps >= limits.minimum_constant_steps )
      {
        ConstantTargetCandidate candidate;
        candidate.instruction = insn.address;
        candidate.target = value->second.value;
        candidate.kind = insn.kind == InstructionKind::IndirectCall
                       ? ConstantTargetKind::IndirectCall
                       : ConstantTargetKind::IndirectJump;
        candidate.register_id = reg;
        candidate.register_name = insn.source_name.empty()
                                ? insn.destination_name : insn.source_name;
        candidate.value_width = value->second.width;
        candidate.transformation_steps = value->second.steps;
        candidate.used_read_only_load = value->second.read_only_load;
        candidate.support = value->second.support;
        candidate.support.push_back(insn.address);
        normalize_support(candidate.support);
        result.targets.push_back(std::move(candidate));
      }
    }

    if ( insn.kind == InstructionKind::PushImmediate )
    {
      ConstantState immediate;
      immediate.value = truncate_width(insn.immediate, insn.value_width);
      immediate.width = insn.value_width;
      immediate.steps = 1;
      immediate.support = { insn.address };
      pending_push = std::make_pair(kNoRegister, std::move(immediate));
    }
    else if ( insn.kind == InstructionKind::PushRegister )
    {
      const auto value = state.find(insn.source_register);
      if ( value != state.end()
        && (insn.value_width == 0
         || value->second.width == insn.value_width) )
        pending_push = std::make_pair(insn.source_register, value->second);
      else
        pending_push.reset();
    }
    else if ( insn.kind == InstructionKind::Return )
    {
      if ( pending_push.has_value()
        && (pending_push->first == kNoRegister
         || pending_push->second.steps >= limits.minimum_constant_steps) )
      {
        ConstantTargetCandidate candidate;
        candidate.instruction = insn.address;
        candidate.target = pending_push->second.value;
        candidate.kind = ConstantTargetKind::PushReturn;
        candidate.register_id = pending_push->first;
        candidate.value_width = pending_push->second.width;
        candidate.transformation_steps = pending_push->second.steps;
        candidate.used_read_only_load = pending_push->second.read_only_load;
        candidate.support = pending_push->second.support;
        candidate.support.push_back(insn.address);
        normalize_support(candidate.support);
        result.targets.push_back(std::move(candidate));
      }
      pending_push.reset();
    }
    else if ( insn.kind != InstructionKind::Nop )
    {
      // Only an adjacent push/nop*/ret is accepted as a push-return gadget.
      if ( pending_push.has_value()
        && insn.kind != InstructionKind::PushRegister
        && insn.kind != InstructionKind::PushImmediate )
      {
        pending_push.reset();
      }
    }

    update_constants(state, insn);
  }

  result.final_assignments.reserve(state.size());
  for ( const auto &item : state )
  {
    ConstantAssignment assignment;
    assignment.register_id = item.first;
    assignment.value = item.second.value;
    assignment.value_width = item.second.width;
    assignment.transformation_steps = item.second.steps;
    assignment.support = item.second.support;
    assignment.instruction = assignment.support.empty()
                           ? kBadAddress : assignment.support.back();
    result.final_assignments.push_back(std::move(assignment));
  }
  std::sort(result.final_assignments.begin(), result.final_assignments.end(),
            [](const ConstantAssignment &a, const ConstantAssignment &b)
            { return a.register_id < b.register_id; });
  std::sort(result.targets.begin(), result.targets.end(),
            [](const ConstantTargetCandidate &a,
               const ConstantTargetCandidate &b)
            {
              if ( a.instruction != b.instruction )
                return a.instruction < b.instruction;
              if ( a.target != b.target )
                return a.target < b.target;
              return a.kind < b.kind;
            });
  return result;
}

std::vector<DispatchCandidate> find_dispatch_candidates(
    const std::vector<Block> &blocks,
    const ClassifierLimits &limits)
{
  std::vector<DispatchCandidate> out;
  if ( limits.minimum_dispatch_cases == 0
    || limits.maximum_dispatch_cases < limits.minimum_dispatch_cases )
  {
    return out;
  }

  std::map<uint64_t, DispatchNode> nodes;
  for ( const Block &block : blocks )
  {
    const auto parsed = parse_dispatch_node(block);
    if ( parsed.has_value() )
      nodes.emplace(parsed->block, *parsed);
  }
  if ( nodes.empty() )
    return out;

  std::set<uint64_t> compatible_next_targets;
  for ( const auto &item : nodes )
  {
    const auto next = nodes.find(item.second.next);
    if ( next != nodes.end() && next->second.reg == item.second.reg
      && next->second.width == item.second.width )
      compatible_next_targets.insert(item.second.next);
  }

  std::vector<uint64_t> starts;
  for ( const auto &item : nodes )
    if ( compatible_next_targets.count(item.first) == 0 )
      starts.push_back(item.first);
  // A pure cycle has no natural head.  Analyze its lowest address exactly once.
  if ( starts.empty() )
    starts.push_back(nodes.begin()->first);

  std::set<uint64_t> emitted_sites;
  for ( uint64_t start : starts )
  {
    std::vector<DispatchNode> chain;
    std::set<uint64_t> visited;
    uint64_t cursor = start;
    int32_t state_reg = kNoRegister;
    while ( chain.size() < limits.maximum_dispatch_cases )
    {
      const auto found = nodes.find(cursor);
      if ( found == nodes.end() || !visited.insert(cursor).second )
        break;
      if ( state_reg == kNoRegister )
        state_reg = found->second.reg;
      if ( found->second.reg != state_reg
        || (!chain.empty() && found->second.width != chain.front().width) )
        break;
      chain.push_back(found->second);
      cursor = found->second.next;
    }
    if ( chain.size() < limits.minimum_dispatch_cases
      || !emitted_sites.insert(chain.front().site).second )
    {
      continue;
    }

    std::map<uint64_t, uint64_t> selector_targets;
    bool contradiction = false;
    for ( const DispatchNode &node : chain )
    {
      const auto prior = selector_targets.find(node.selector);
      if ( prior != selector_targets.end() && prior->second != node.case_target )
      {
        contradiction = true;
        break;
      }
      selector_targets[node.selector] = node.case_target;
    }
    if ( contradiction || selector_targets.size() < limits.minimum_dispatch_cases )
      continue;

    DispatchCandidate candidate;
    candidate.entry_block = start;
    candidate.site = chain.front().site;
    candidate.state_register = state_reg;
    candidate.state_register_name = chain.front().reg_name;
    candidate.state_width = chain.front().width;
    candidate.selector_one_bit_percent = selector_entropy(chain);
    for ( const auto &item : selector_targets )
      candidate.cases.push_back({ item.first, item.second });
    for ( const DispatchNode &node : chain )
      candidate.comparison_sites.push_back(node.site);
    if ( visited.count(cursor) == 0 && cursor != kBadAddress )
      candidate.default_target = cursor;

    for ( const Block &block : blocks )
    {
      if ( visited.count(block.start) != 0 )
        continue;
      if ( std::find(block.successors.begin(), block.successors.end(), start)
        != block.successors.end() )
      {
        candidate.loop_backed = true;
        break;
      }
    }
    out.push_back(std::move(candidate));
  }

  std::sort(out.begin(), out.end(),
            [](const DispatchCandidate &a, const DispatchCandidate &b)
            { return a.site < b.site; });
  return out;
}

} // namespace deobf
} // namespace viy
