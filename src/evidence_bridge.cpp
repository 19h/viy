#include "evidence_bridge.hpp"

#include <algorithm>
#include <limits>
#include <string>

namespace viy {

namespace {

using namespace analysis;

Evidence make_evidence(const FuncRange &function, uint32_t run_id,
                       uint64_t seed, const char *method,
                       std::vector<Address> support = {})
{
  Evidence e;
  e.producer = "viy.rax.emulator";
  e.method = method;
  e.proof = ProofKind::Observed;
  e.confidence = 8500; // concrete semantics under a synthesized entry state
  e.scope.run_id = uint64_t(run_id);
  e.scope.seed = seed;
  e.scope.function_start = function.start;
  uint64_t end = function.end;
  for ( const FuncChunk &chunk : function.chunks )
    end = std::max(end, chunk.end);
  e.scope.function_end = end;
  e.scope.generation = function.generation;
  e.support_addresses = std::move(support);
  return e;
}

void account(EvidenceBridgeStats &stats, const AddResult &result)
{
  switch ( result.disposition )
  {
    case AddDisposition::InsertedRecord: ++stats.inserted_records; break;
    case AddDisposition::AddedObservation: ++stats.added_observations; break;
    case AddDisposition::DuplicateObservation: ++stats.duplicates; break;
    case AddDisposition::RejectedInvalid: ++stats.rejected; break;
  }
}

MemoryAccessKind access_kind(int kind)
{
  return kind == RAX_MEM_WRITE ? MemoryAccessKind::Write : MemoryAccessKind::Read;
}

std::vector<uint8_t> scalar_bytes(uint64_t value, uint32_t size, bool big_endian_memory)
{
  const uint32_t n = std::min<uint32_t>(size, 8);
  std::vector<uint8_t> bytes(n);
  for ( uint32_t i = 0; i < n; ++i )
  {
    const uint32_t shift = big_endian_memory ? (n - 1 - i) : i;
    bytes[i] = uint8_t(value >> (8 * shift));
  }
  return bytes;
}

std::string register_name(ViyArch arch, int reg)
{
  static const char *x86_64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
  static const char *x86_32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
  switch ( arch )
  {
    case ViyArch::X86_64:
      if ( reg >= RAX_X86_GPR64(0) && reg <= RAX_X86_GPR64(15) )
        return std::string("x86:") + x86_64[reg - RAX_X86_GPR64(0)];
      if ( reg == RAX_X86_REG_RIP ) return "x86:rip";
      break;
    case ViyArch::X86_32:
      if ( reg >= RAX_X86_GPR32(0) && reg <= RAX_X86_GPR32(7) )
        return std::string("x86:") + x86_32[reg - RAX_X86_GPR32(0)];
      if ( reg == RAX_X86_REG_EIP ) return "x86:eip";
      break;
    case ViyArch::ARM64:
      if ( reg >= RAX_ARM64_X(0) && reg <= RAX_ARM64_X(30) )
        return "arm64:x" + std::to_string(reg - RAX_ARM64_X(0));
      if ( reg == RAX_ARM64_REG_SP ) return "arm64:sp";
      if ( reg == RAX_ARM64_REG_PC ) return "arm64:pc";
      break;
    case ViyArch::ARM32:
      if ( reg >= RAX_ARM_R(0) && reg <= RAX_ARM_R(12) )
        return "arm:r" + std::to_string(reg - RAX_ARM_R(0));
      if ( reg == RAX_ARM_REG_SP ) return "arm:sp";
      if ( reg == RAX_ARM_REG_LR ) return "arm:lr";
      if ( reg == RAX_ARM_REG_PC ) return "arm:pc";
      break;
    case ViyArch::CORTEX_M:
      if ( reg >= RAX_CM_R(0) && reg <= RAX_CM_R(12) )
        return "cortexm:r" + std::to_string(reg - RAX_CM_R(0));
      if ( reg == RAX_REG_SP ) return "cortexm:sp";
      if ( reg == RAX_CM_REG_LR ) return "cortexm:lr";
      if ( reg == RAX_CM_REG_PC ) return "cortexm:pc";
      break;
    case ViyArch::RISCV64:
      if ( reg >= RAX_RISCV_X(0) && reg <= RAX_RISCV_X(31) )
        return "riscv:x" + std::to_string(reg - RAX_RISCV_X(0));
      if ( reg == RAX_RISCV_REG_PC ) return "riscv:pc";
      break;
    case ViyArch::HEXAGON:
      if ( reg >= RAX_HEX_R(0) && reg <= RAX_HEX_R(31) )
        return "hexagon:r" + std::to_string(reg - RAX_HEX_R(0));
      if ( reg == RAX_HEX_REG_PC ) return "hexagon:pc";
      break;
    default:
      break;
  }
  return "rax:" + std::to_string(int(arch)) + ":" + std::to_string(reg);
}

CodeTargetKind target_kind(ExecEdge::Kind kind)
{
  switch ( kind )
  {
    case ExecEdge::Kind::Call: return CodeTargetKind::Call;
    case ExecEdge::Kind::Jump: return CodeTargetKind::Jump;
    case ExecEdge::Kind::Return: return CodeTargetKind::Return;
    default: return CodeTargetKind::Unknown;
  }
}

CfgEdgeKind cfg_kind(ExecEdge::Kind kind)
{
  switch ( kind )
  {
    case ExecEdge::Kind::Call: return CfgEdgeKind::Call;
    case ExecEdge::Kind::Return: return CfgEdgeKind::Return;
    case ExecEdge::Kind::Jump: return CfgEdgeKind::Indirect;
    default: return CfgEdgeKind::Unknown;
  }
}

bool valid_image_range(const ProgramImage &img, uint64_t address, size_t size)
{
  if ( size == 0 || uint64_t(size) > std::numeric_limits<uint64_t>::max() - address )
    return false;
  const uint64_t end = address + uint64_t(size);
  for ( const SegImage &segment : img.segs )
    if ( address >= segment.start && address < segment.end && end <= segment.end )
      return true;
  return false;
}

} // namespace

EvidenceBridgeStats viy_record_emulation_evidence(
    analysis::EvidenceStore &store,
    const ProgramImage &img,
    const FuncRange &function,
    const EmuEvents &events,
    const std::vector<ObservedOutcome> &outcomes)
{
  EvidenceBridgeStats stats;
  for ( const ExecEdge &edge : events.edges )
  {
    // A sentinel return and a fault escape are emulator-control addresses, not
    // locations in the IDB. FunctionOutcome records termination separately.
    if ( edge.kind == ExecEdge::Kind::Unknown
      || img.segment_at(edge.from) == nullptr || img.segment_at(edge.to) == nullptr )
      continue;
    AnalysisFact target;
    target.payload = CodeTargetFact{ edge.from, edge.to, target_kind(edge.kind), false };
    target.evidence = make_evidence(function, edge.run_id, edge.seed,
                                    "executed-control-transfer", { edge.from, edge.to });
    account(stats, store.add(std::move(target)));

    AnalysisFact reached;
    reached.payload = BranchReachabilityFact{ edge.from, edge.to, Reachability::Reached };
    reached.evidence = make_evidence(function, edge.run_id, edge.seed,
                                     "executed-successor", { edge.from, edge.to });
    account(stats, store.add(std::move(reached)));

    AnalysisFact cfg;
    cfg.payload = CfgCandidateFact{ edge.from, edge.to, cfg_kind(edge.kind),
                                    Reachability::Reached };
    cfg.evidence = make_evidence(function, edge.run_id, edge.seed,
                                 "executed-cfg-edge", { edge.from, edge.to });
    account(stats, store.add(std::move(cfg)));

    if ( edge.kind == ExecEdge::Kind::Call )
    {
      AnalysisFact call;
      CallObservationFact payload;
      payload.source = edge.from;
      payload.target = edge.to;
      payload.kind = CallKind::Call;
      payload.result = CallResult::Unknown;
      call.payload = std::move(payload);
      call.evidence = make_evidence(function, edge.run_id, edge.seed,
                                    "executed-call", { edge.from, edge.to });
      account(stats, store.add(std::move(call)));
    }
  }

  for ( const DataAcc &access : events.data )
  {
    // The evidence schema currently has a single program-address space.  Do
    // not persist fabricated emulator stack/heap addresses as if they were IDB
    // addresses; runtime enrichment consumes those transient events directly.
    if ( access.scope != DataScope::IMAGE || access.size == 0
      || (access.kind != RAX_MEM_READ && access.kind != RAX_MEM_WRITE)
      || !valid_image_range(img, access.addr, access.size) )
      continue;
    AnalysisFact fact;
    fact.payload = MemoryAccessFact{ access.from, access.addr, access.size,
                                     access_kind(access.kind) };
    fact.evidence = make_evidence(function, access.run_id, access.seed,
                                  "memory-access", { access.from, access.addr });
    account(stats, store.add(std::move(fact)));
    if ( access.size <= 8 )
    {
      AnalysisFact value;
      value.payload = MemoryValueFact{ access.from, access.addr,
                                       access_kind(access.kind),
                                       scalar_bytes(access.value, access.size, img.big_endian) };
      value.evidence = make_evidence(function, access.run_id, access.seed,
                                     "memory-value", { access.from, access.addr });
      account(stats, store.add(std::move(value)));
    }
  }

  for ( const StatePoint &point : events.states )
  {
    for ( const RegisterValue &reg : point.regs )
    {
      if ( reg.width == 0 || reg.width > 8 )
        continue;
      AnalysisFact value;
      value.payload = RegisterValueFact{ point.pc, RegisterStatePoint::BeforeInstruction,
                                         register_name(img.arch, reg.reg),
                                         scalar_bytes(reg.value, reg.width, false) };
      value.evidence = make_evidence(function, point.run_id, point.seed,
                                     "transfer-target-register-state",
                                     { point.source, point.pc });
      account(stats, store.add(std::move(value)));
    }
  }

  for ( const MemoryBytes &memory : events.final_writes )
  {
    if ( memory.scope != DataScope::IMAGE || memory.bytes.empty()
      || !valid_image_range(img, memory.addr, memory.bytes.size()) )
      continue;
    uint64_t instruction = function.start;
    uint64_t best_sequence = 0;
    bool found = false;
    for ( const DataAcc &access : events.data )
    {
      if ( access.run_id != memory.run_id || access.seed != memory.seed
        || access.kind != RAX_MEM_WRITE || access.scope != DataScope::IMAGE
        || access.size == 0 )
        continue;
      const uint64_t memory_size = uint64_t(memory.bytes.size());
      if ( memory_size > std::numeric_limits<uint64_t>::max() - memory.addr
        || uint64_t(access.size) > std::numeric_limits<uint64_t>::max() - access.addr )
        continue;
      if ( access.addr < memory.addr + memory_size
        && memory.addr < access.addr + uint64_t(access.size)
        && (!found || access.sequence >= best_sequence) )
      {
        instruction = access.from;
        best_sequence = access.sequence;
        found = true;
      }
    }
    AnalysisFact value;
    value.payload = MemoryValueFact{ instruction, memory.addr,
                                     MemoryAccessKind::Write, memory.bytes };
    value.evidence = make_evidence(function, memory.run_id, memory.seed,
                                   "final-written-bytes", { instruction, memory.addr });
    account(stats, store.add(std::move(value)));
  }

  for ( const ObservedOutcome &observed : outcomes )
  {
    FunctionStopKind stop = FunctionStopKind::Unknown;
    if ( observed.outcome.returned ) stop = FunctionStopKind::Returned;
    else if ( observed.outcome.terminated_process ) stop = FunctionStopKind::TerminatedProcess;
    else
    {
      switch ( observed.outcome.stop_reason )
      {
        case RAX_STOP_HLT:
        case RAX_STOP_SHUTDOWN: stop = FunctionStopKind::Halted; break;
        case RAX_STOP_TIMEOUT: stop = FunctionStopKind::TimedOut; break;
        case RAX_STOP_COUNT: stop = FunctionStopKind::BudgetExhausted; break;
        case RAX_STOP_EXCEPTION: stop = FunctionStopKind::Faulted; break;
        default: break;
      }
    }
    AnalysisFact outcome;
    FunctionOutcomeFact payload;
    payload.function = function.start;
    payload.stop = stop;
    if ( observed.outcome.stop_valid )
      payload.stop_pc = observed.outcome.stop_pc;
    if ( observed.outcome.sp_valid )
      payload.stack_delta = observed.outcome.sp_delta;
    payload.instruction_count = observed.outcome.instruction_count;
    outcome.payload = std::move(payload);
    outcome.evidence = make_evidence(function, observed.run_id, observed.seed,
                                     "function-outcome", { function.start });
    account(stats, store.add(std::move(outcome)));
  }
  return stats;
}

} // namespace viy
