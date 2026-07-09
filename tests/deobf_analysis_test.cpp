#include "analysis_facts.hpp"
#include "deobf_analysis.hpp"
#include "deobf_analysis_core.hpp"
#include "evidence_store.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace viy;
using namespace viy::deobf;

[[noreturn]] void fail(const char *expression, int line)
{
  std::cerr << "deobf analysis test failure at line " << line
            << ": " << expression << '\n';
  std::exit(1);
}

#define CHECK(expression) \
  do { if ( !(expression) ) fail(#expression, __LINE__); } while ( false )

Instruction insn(uint64_t ea, InstructionKind kind, uint16_t size = 1)
{
  Instruction out;
  out.address = ea;
  out.size = size;
  out.kind = kind;
  out.flag_effect = FlagEffect::Preserve;
  return out;
}

Instruction load(uint64_t ea, int32_t reg, uint64_t value,
                 uint8_t width = 8)
{
  Instruction out = insn(ea, InstructionKind::LoadImmediate);
  out.destination_register = reg;
  out.destination_name = "r" + std::to_string(reg);
  out.value_width = width;
  out.immediate = value;
  return out;
}

Instruction update(uint64_t ea, InstructionKind kind, int32_t reg,
                   uint64_t value, uint8_t width = 8)
{
  Instruction out = insn(ea, kind);
  out.destination_register = reg;
  out.source_register = reg;
  out.destination_name = "r" + std::to_string(reg);
  out.source_name = out.destination_name;
  out.value_width = width;
  out.immediate = value;
  out.flag_effect = FlagEffect::UnknownWrite;
  return out;
}

Instruction conditional(uint64_t ea, uint64_t target,
                        X86Condition condition)
{
  Instruction out = insn(ea, InstructionKind::ConditionalBranch);
  out.target = target;
  out.condition = condition;
  out.flag_effect = FlagEffect::Preserve;
  return out;
}

void test_get_pc()
{
  Instruction call = insn(0x1000, InstructionKind::DirectCall, 5);
  call.target = 0x1010;

  Instruction pop = insn(0x1010, InstructionKind::PopRegister);
  pop.destination_register = 1;
  pop.destination_name = "rax";
  pop.value_width = 8;
  Instruction add = update(0x1011, InstructionKind::AddImmediate, 1, 7);
  Instruction push = insn(0x1012, InstructionKind::PushRegister);
  push.source_register = 1;
  push.source_name = "rax";
  push.value_width = 8;
  Instruction ret = insn(0x1013, InstructionKind::Return);

  auto found = classify_get_pc_gadget(call, { pop, add, push, ret }, false);
  CHECK(found.has_value());
  CHECK(found->mode == GetPcMode::PopReturnAddress);
  CHECK(found->resumed_at == 0x100c);
  CHECK(found->register_value_at_return == 0x100c);
  CHECK(found->return_instruction == 0x1013);

  CHECK(!classify_get_pc_gadget(call, { pop, add, push, ret }, true).has_value());
  push.alternate_predecessor = true;
  CHECK(!classify_get_pc_gadget(call, { pop, add, push, ret }, false).has_value());

  Instruction read = pop;
  read.kind = InstructionKind::ReadStackTop;
  CHECK(!classify_get_pc_gadget(call, { read, ret }, false).has_value());

  Instruction adjust = insn(0x1010, InstructionKind::AddStackTopImmediate);
  adjust.immediate = 4;
  ret.address = 0x1011;
  found = classify_get_pc_gadget(call, { adjust, ret }, false);
  CHECK(found.has_value());
  CHECK(found->mode == GetPcMode::AdjustReturnAddress);
  CHECK(found->resumed_at == 0x1009);

  Instruction discard = insn(0x1010,
      InstructionKind::AdjustStackPointerImmediate);
  discard.immediate = 8;
  found = classify_get_pc_gadget(call, { discard }, false);
  CHECK(found.has_value());
  CHECK(found->mode == GetPcMode::DiscardReturnAddress);

  pop.address = 0x1010;
  Instruction subtract = update(
      0x1011, InstructionKind::SubImmediate, 1, 2);
  push.address = 0x1012;
  push.alternate_predecessor = false;
  ret.address = 0x1013;
  found = classify_get_pc_gadget(call, { pop, subtract, push, ret }, false);
  CHECK(found.has_value() && found->resumed_at == 0x1003);

  Instruction add_after_push = update(
      0x1013, InstructionKind::AddImmediate, 1, 9);
  ret.address = 0x1014;
  push.address = 0x1012;
  subtract.address = 0x1011;
  found = classify_get_pc_gadget(
      call, { pop, subtract, push, add_after_push, ret }, false);
  CHECK(found.has_value());
  CHECK(found->resumed_at == 0x1003); // stack captured before later reg update
  CHECK(found->register_value_at_return == 0x100c);

  Instruction other_push = insn(0x1013, InstructionKind::PushRegister);
  other_push.source_register = 2;
  ret.address = 0x1014;
  CHECK(!classify_get_pc_gadget(
      call, { pop, subtract, push, other_push, ret }, false).has_value());

  Instruction stop = insn(0x1011, InstructionKind::IndirectJump);
  CHECK(!classify_get_pc_gadget(call, { pop, stop }, false).has_value());

  call.target = call.end();
  CHECK(!classify_get_pc_gadget(call, { adjust, ret }, false).has_value());
}

void test_gap()
{
  Instruction jump = insn(0x2000, InstructionKind::DirectJump, 2);
  jump.target = 0x2010;
  auto gap = classify_jump_gap(jump, true, true);
  CHECK(gap.has_value());
  CHECK(gap->start == 0x2002 && gap->end == 0x2010);
  CHECK(!classify_jump_gap(jump, false, true).has_value());
  CHECK(!classify_jump_gap(jump, true, false).has_value());
  ClassifierLimits tight;
  tight.maximum_gap = 4;
  CHECK(!classify_jump_gap(jump, true, true, tight).has_value());
}

void test_entry_predicates()
{
  Instruction move = load(0x3000, 1, 7, 4);
  Instruction branch = conditional(0x3001, 0x3010, X86Condition::Zero);
  auto undefined = classify_entry_predicate(0x3000, { move, branch });
  CHECK(undefined.has_value());
  CHECK(undefined->knowledge == PredicateKnowledge::EntryFlagsUnspecified);
  CHECK(!undefined->taken.has_value());

  Instruction compare = insn(0x3001, InstructionKind::CompareImmediate);
  compare.destination_register = 1;
  compare.destination_name = "eax";
  compare.value_width = 4;
  compare.immediate = 7;
  compare.flag_effect = FlagEffect::KnownCompare;
  branch.address = 0x3002;
  auto exact = classify_entry_predicate(0x3000, { move, compare, branch });
  CHECK(exact.has_value());
  CHECK(exact->knowledge == PredicateKnowledge::ConstantOutcome);
  CHECK(exact->taken == true);

  compare.immediate = 8;
  branch.condition = X86Condition::Less;
  exact = classify_entry_predicate(0x3000, { move, compare, branch });
  CHECK(exact.has_value() && exact->taken == true);

  Instruction call = insn(0x3002, InstructionKind::DirectCall);
  call.target = 0x4000;
  branch.address = 0x3003;
  CHECK(!classify_entry_predicate(
      0x3000, { move, compare, call, branch }).has_value());

  Instruction clobber = insn(0x3001, InstructionKind::Other);
  clobber.flag_effect = FlagEffect::UnknownWrite;
  compare.address = 0x3002;
  branch.address = 0x3003;
  // The later exact compare supersedes an earlier unknown flag writer.
  exact = classify_entry_predicate(
      0x3000, { move, clobber, compare, branch });
  CHECK(exact.has_value() && exact->knowledge == PredicateKnowledge::ConstantOutcome);

  branch.address = 0x3002;
  CHECK(!classify_entry_predicate(0x3000, { move, clobber, branch }).has_value());

  move.immediate = 0x80;
  move.value_width = 1;
  compare.address = 0x3001;
  compare.value_width = 1;
  compare.immediate = 1;
  compare.register_is_left_operand = true;
  branch.address = 0x3002;
  branch.condition = X86Condition::Overflow;
  exact = classify_entry_predicate(0x3000, { move, compare, branch });
  CHECK(exact.has_value() && exact->taken == true); // 0x80 - 1 overflows i8

  move.immediate = 0xf0;
  compare.kind = InstructionKind::TestImmediate;
  compare.flag_effect = FlagEffect::KnownTest;
  compare.immediate = 0x0f;
  branch.condition = X86Condition::NotZero;
  exact = classify_entry_predicate(0x3000, { move, compare, branch });
  CHECK(exact.has_value() && exact->taken == false);

  compare.kind = InstructionKind::CompareImmediate;
  compare.flag_effect = FlagEffect::KnownCompare;
  compare.register_is_left_operand = false;
  compare.immediate = 0xf1;
  branch.condition = X86Condition::Greater;
  exact = classify_entry_predicate(0x3000, { move, compare, branch });
  CHECK(exact.has_value() && exact->taken == true);
}

void test_wrapper()
{
  FunctionShape shape;
  shape.entry = 0x4000;
  shape.end = 0x4004;
  shape.caller_count = 2;
  Instruction move = load(0x4000, 1, 42);
  move.plumbing = true;
  Instruction call = insn(0x4001, InstructionKind::DirectCall);
  call.target = 0x5000;
  Instruction ret = insn(0x4002, InstructionKind::Return);
  shape.instructions = { move, call, ret };
  auto wrapper = classify_wrapper(shape);
  CHECK(wrapper.has_value());
  CHECK(wrapper->target == 0x5000);
  CHECK(wrapper->thunk);

  shape.has_tail_chunks = true;
  CHECK(!classify_wrapper(shape).has_value());
  shape.has_tail_chunks = false;
  shape.instructions[0].writes_global_memory = true;
  CHECK(!classify_wrapper(shape).has_value());

  shape.instructions.clear();
  Instruction jump = insn(0x4000, InstructionKind::DirectJump);
  jump.target = 0x6000;
  shape.instructions.push_back(jump);
  wrapper = classify_wrapper(shape);
  CHECK(wrapper.has_value() && wrapper->tail_call && wrapper->thunk);

  shape.instructions = { call };
  shape.direct_callee_returns = false;
  wrapper = classify_wrapper(shape);
  CHECK(wrapper.has_value());
  shape.direct_callee_returns = true;
  CHECK(!classify_wrapper(shape).has_value());

  Instruction conditional_jump = conditional(
      0x4001, 0x4010, X86Condition::Zero);
  shape.instructions = { call, conditional_jump, ret };
  CHECK(!classify_wrapper(shape).has_value());

  Instruction indirect = insn(0x4001, InstructionKind::IndirectCall);
  shape.instructions = { indirect, ret };
  CHECK(!classify_wrapper(shape).has_value());
}

void test_constants_and_push_ret()
{
  Block block;
  block.start = 0x5000;
  block.end = 0x5004;
  Instruction first = load(0x5000, 1, 0xfffffff0, 4);
  Instruction add = update(0x5001, InstructionKind::AddImmediate, 1, 0x20, 4);
  Instruction jump = insn(0x5002, InstructionKind::IndirectJump);
  jump.source_register = 1;
  jump.source_name = "eax";
  jump.value_width = 4;
  block.instructions = { first, add, jump };
  ConstantBlockResult result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1);
  CHECK(result.targets[0].target == 0x10); // width-aware wrap
  CHECK(result.targets[0].transformation_steps == 2);

  Instruction call = insn(0x5002, InstructionKind::DirectCall);
  call.target = 0x7000;
  jump.address = 0x5003;
  block.instructions = { first, add, call, jump };
  CHECK(analyze_constant_block(block).targets.empty());

  Instruction ro = load(0x5000, 2, 0x8000);
  ro.kind = InstructionKind::LoadReadOnlyConstant;
  ro.memory_address = 0x9000;
  Instruction x = update(0x5001, InstructionKind::XorImmediate, 2, 0x10);
  Instruction indirect_call = insn(0x5002, InstructionKind::IndirectCall);
  indirect_call.source_register = 2;
  indirect_call.source_name = "rax";
  block.instructions = { ro, x, indirect_call };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1 && result.targets[0].used_read_only_load);
  CHECK(result.targets[0].target == 0x8010);

  Instruction push = insn(0x5002, InstructionKind::PushRegister);
  push.source_register = 2;
  Instruction ret = insn(0x5003, InstructionKind::Return);
  block.instructions = { ro, x, push, ret };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1);
  CHECK(result.targets[0].kind == ConstantTargetKind::PushReturn);
  CHECK(result.targets[0].target == 0x8010);

  Instruction push_immediate = insn(0x5000, InstructionKind::PushImmediate);
  push_immediate.immediate = 0x1234;
  push_immediate.value_width = 8;
  ret.address = 0x5001;
  block.instructions = { push_immediate, ret };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1 && result.targets[0].target == 0x1234);

  Instruction noise = insn(0x5001, InstructionKind::Other);
  ret.address = 0x5002;
  block.instructions = { push_immediate, noise, ret };
  CHECK(analyze_constant_block(block).targets.empty());

  Instruction copy = insn(0x5001, InstructionKind::CopyRegister);
  copy.destination_register = 3;
  copy.source_register = 2;
  copy.destination_name = "r3";
  copy.value_width = 8;
  Instruction subtract = update(
      0x5002, InstructionKind::SubImmediate, 3, 0x10);
  Instruction bit_and = update(
      0x5003, InstructionKind::AndImmediate, 3, 0xffff);
  Instruction bit_or = update(
      0x5004, InstructionKind::OrImmediate, 3, 0x10000);
  Instruction shift = update(
      0x5005, InstructionKind::ShiftLeftImmediate, 3, 1);
  jump.address = 0x5006;
  jump.source_register = 3;
  jump.source_name = "r3";
  jump.value_width = 8;
  block.instructions = { ro, copy, subtract, bit_and, bit_or, shift, jump };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1);
  CHECK(result.targets[0].target == 0x2ffe0);

  Instruction low = load(0x5000, 4, 0x5678, 4);
  Instruction high = update(
      0x5001, InstructionKind::ReplaceHigh16, 4, 0x1234, 4);
  jump.address = 0x5002;
  jump.source_register = 4;
  jump.source_name = "r4";
  jump.value_width = 4;
  block.instructions = { low, high, jump };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1);
  CHECK(result.targets[0].target == 0x12345678);

  Instruction arm_add = update(
      0x5001, InstructionKind::AddImmediate, 5, 3, 8);
  arm_add.source_register = 4;
  jump.address = 0x5002;
  jump.source_register = 5;
  jump.value_width = 8;
  block.instructions = { load(0x5000, 4, 9), arm_add, jump };
  result = analyze_constant_block(block);
  CHECK(result.targets.size() == 1 && result.targets[0].target == 12);

  shift = update(0x5001, InstructionKind::ShiftLeftImmediate, 4, 64);
  block.instructions = { load(0x5000, 4, 1), shift, jump };
  CHECK(analyze_constant_block(block).targets.empty());
}

Block dispatch_block(uint64_t start, uint64_t selector,
                     uint64_t case_target, uint64_t next, int32_t reg = 7)
{
  Block block;
  block.start = start;
  block.end = start + 2;
  block.successors = { case_target, next };
  Instruction compare = insn(start, InstructionKind::CompareImmediate);
  compare.destination_register = reg;
  compare.destination_name = "state";
  compare.value_width = 4;
  compare.immediate = selector;
  compare.flag_effect = FlagEffect::KnownCompare;
  Instruction branch = conditional(start + 1, case_target, X86Condition::Zero);
  block.instructions = { compare, branch };
  return block;
}

void test_dispatch()
{
  Block a = dispatch_block(0x6000, 0x12345678, 0x7000, 0x6002);
  Block b = dispatch_block(0x6002, 0x9abcdef0, 0x7010, 0x6004);
  Block c = dispatch_block(0x6004, 0x0f0f0f0f, 0x7020, 0x6006);
  Block body;
  body.start = 0x7000;
  body.end = 0x7001;
  body.successors = { 0x6000 };
  auto maps = find_dispatch_candidates({ a, b, c, body });
  CHECK(maps.size() == 1);
  CHECK(maps[0].entry_block == 0x6000);
  CHECK(maps[0].cases.size() == 3);
  CHECK(maps[0].default_target == 0x6006);
  CHECK(maps[0].loop_backed);
  CHECK(maps[0].selector_one_bit_percent > 20);

  c.instructions[0].immediate = 0x12345678;
  c.instructions[1].target = 0x7999;
  c.successors[0] = 0x7999;
  CHECK(find_dispatch_candidates({ a, b, c, body }).empty());

  ClassifierLimits impossible;
  impossible.minimum_dispatch_cases = 4;
  impossible.maximum_dispatch_cases = 3;
  CHECK(find_dispatch_candidates({ a, b, c }, impossible).empty());

  auto jne_node = [](uint64_t start, uint64_t selector,
                     uint64_t case_target, uint64_t next)
  {
    Block block;
    block.start = start;
    block.end = start + 2;
    block.successors = { case_target, next };
    Instruction compare = insn(start, InstructionKind::CompareImmediate);
    compare.destination_register = 9;
    compare.destination_name = "state2";
    compare.value_width = 4;
    compare.immediate = selector;
    compare.flag_effect = FlagEffect::KnownCompare;
    Instruction branch = conditional(
        start + 1, next, X86Condition::NotZero);
    block.instructions = { compare, branch };
    return block;
  };
  Block x = jne_node(0xa000, 1, 0xa002, 0xa010);
  Block y = jne_node(0xa010, 2, 0xa012, 0xa020);
  Block z = jne_node(0xa020, 3, 0xa022, 0xa000);
  maps = find_dispatch_candidates({ x, y, z });
  CHECK(maps.size() == 1);
  CHECK(maps[0].cases.size() == 3);
  CHECK(!maps[0].default_target.has_value());

  Instruction overwrite = load(0xa000, 9, 99, 4);
  x.instructions.insert(x.instructions.begin(), overwrite);
  x.instructions[1].address = 0xa001;
  x.instructions[2].address = 0xa002;
  x.end = 0xa003;
  x.successors[0] = 0xa003;
  CHECK(find_dispatch_candidates({ x, y, z }).empty());
}

analysis::Evidence evidence(const char *producer)
{
  analysis::Evidence out;
  out.producer = producer;
  out.method = "test";
  out.proof = analysis::ProofKind::StaticProof;
  out.confidence = 9000;
  return out;
}

analysis::Evidence evidence_at(
    const char *producer,
    uint64_t generation,
    analysis::ProofKind proof = analysis::ProofKind::StaticProof)
{
  analysis::Evidence out = evidence(producer);
  out.scope.generation = generation;
  out.proof = proof;
  return out;
}

void test_contradiction_gate()
{
  analysis::EvidenceStore store;
  analysis::CodeTargetFact left;
  left.from = 0x8000;
  left.target = 0x8100;
  left.kind = analysis::CodeTargetKind::Jump;
  left.unique = true;
  CHECK(store.add({ left, evidence("first") }).disposition
        == analysis::AddDisposition::InsertedRecord);

  DeobfEvidenceStoreSink sink(store);
  analysis::CodeTargetFact right = left;
  right.target = 0x8200;
  sink.emit_deobf_fact({ right, evidence("viy.deobf.ida") });
  CHECK(sink.report().contradictions_suppressed == 1);
  CHECK(store.record_count() == 1);

  // A new observation of the existing payload is valid corroboration even if
  // another preexisting record were in conflict with it.
  sink.emit_deobf_fact({ left, evidence("viy.deobf.ida") });
  CHECK(sink.report().added_observations == 1);
  CHECK(store.observation_count() == 2);

  // Incomplete competing dispatch maps are ambiguities, not contradictions;
  // both remain available to downstream policy.
  analysis::DispatchMapFact one;
  one.site = 0x9000;
  one.cases = { { 1, 0x9100 } };
  analysis::DispatchMapFact two = one;
  two.cases = { { 1, 0x9200 } };
  sink.emit_deobf_fact({ one, evidence("viy.deobf.ida") });
  sink.emit_deobf_fact({ two, evidence("viy.deobf.ida") });
  CHECK(sink.report().inserted_records == 2);
  CHECK(store.record_count() == 3);

  sink.emit_deobf_fact({ one, evidence("viy.deobf.ida") });
  CHECK(sink.report().duplicate_observations == 1);

  analysis::AnalysisFact invalid{ one, evidence("") };
  sink.emit_deobf_fact(invalid);
  CHECK(sink.report().rejected_invalid == 1);
  CHECK(std::string(sink.last_error()).size() > 0);
  sink.reset_report();
  CHECK(sink.report().inserted_records == 0);
  CHECK(std::string(sink.last_error()).empty());
}

void test_generation_aware_contradiction_gate()
{
  analysis::CodeTargetFact historical;
  historical.from = 0xa100;
  historical.target = 0xa200;
  historical.kind = analysis::CodeTargetKind::Jump;
  historical.unique = true;
  analysis::CodeTargetFact fresh = historical;
  fresh.target = 0xa300;

  // A contradiction that exists only in a stale snapshot must not veto new
  // evidence. Both payloads and both generations remain in the full ledger.
  analysis::EvidenceStore history;
  CHECK(history.add({ historical, evidence_at("old", 11) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  DeobfEvidenceStoreSink fresh_sink(history);
  fresh_sink.set_active_generation(12);
  CHECK(fresh_sink.emit_deobf_fact(
      { fresh, evidence_at("viy.deobf.ida", 12) }));
  CHECK(fresh_sink.report().contradictions_suppressed == 0);
  CHECK(fresh_sink.report().inserted_records == 1);
  CHECK(history.record_count() == 2);
  CHECK(history.observation_count() == 2);
  CHECK(!history.detect_conflicts().empty());
  const analysis::EvidenceRecord *old_record = history.find(historical);
  const analysis::EvidenceRecord *new_record = history.find(fresh);
  CHECK(old_record != nullptr && old_record->observations.size() == 1);
  CHECK(new_record != nullptr && new_record->observations.size() == 1);
  CHECK(old_record->observations[0].scope.generation == 11);
  CHECK(new_record->observations[0].scope.generation == 12);

  std::vector<uint8_t> blob;
  std::string codec_error;
  CHECK(history.serialize(blob, &codec_error));
  analysis::EvidenceStore restored;
  CHECK(analysis::EvidenceStore::deserialize(blob, restored, &codec_error));
  CHECK(restored.record_count() == 2);
  CHECK(restored.observation_count() == 2);
  CHECK(!restored.detect_conflicts().empty());

  // Even a ledger that already contains a complete stale contradiction does
  // not veto a third, fresh snapshot value: no stale payload is active.
  analysis::EvidenceStore stale_conflicted;
  CHECK(stale_conflicted.add(
      { historical, evidence_at("stale-a", 15) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  CHECK(stale_conflicted.add(
      { fresh, evidence_at("stale-b", 15) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  CHECK(!stale_conflicted.detect_conflicts().empty());
  analysis::CodeTargetFact newest = historical;
  newest.target = 0xa400;
  DeobfEvidenceStoreSink newest_sink(stale_conflicted);
  newest_sink.set_active_generation(16);
  CHECK(newest_sink.emit_deobf_fact(
      { newest, evidence_at("viy.deobf.ida", 16) }));
  CHECK(newest_sink.report().contradictions_suppressed == 0);
  CHECK(stale_conflicted.record_count() == 3);
  CHECK(stale_conflicted.observation_count() == 3);
  CHECK(stale_conflicted.detect_conflicts().size() >= 3);

  // The same semantic disagreement in the active generation is new and must
  // be suppressed transactionally.
  analysis::EvidenceStore current;
  CHECK(current.add({ historical, evidence_at("current-a", 21) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  DeobfEvidenceStoreSink current_sink(current);
  current_sink.set_active_generation(21);
  CHECK(!current_sink.emit_deobf_fact(
      { fresh, evidence_at("viy.deobf.ida", 21) }));
  CHECK(current_sink.report().contradictions_suppressed == 1);
  CHECK(current.record_count() == 1);
  CHECK(current.observation_count() == 1);
  CHECK(current.find(fresh) == nullptr);

  // Explicit user assertions remain active across generation boundaries and
  // therefore veto a contradictory static candidate from a newer snapshot.
  analysis::EvidenceStore asserted;
  CHECK(asserted.add({ historical,
      evidence_at("user", 3, analysis::ProofKind::UserAsserted) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  DeobfEvidenceStoreSink asserted_sink(asserted);
  asserted_sink.set_active_generation(30);
  CHECK(!asserted_sink.emit_deobf_fact(
      { fresh, evidence_at("viy.deobf.ida", 30) }));
  CHECK(asserted_sink.report().contradictions_suppressed == 1);
  CHECK(asserted.record_count() == 1);
  CHECK(asserted.find(historical) != nullptr);
  CHECK(asserted.find(fresh) == nullptr);
}

void test_generation_reactivation_and_existing_conflicts()
{
  analysis::CodeTargetFact left;
  left.from = 0xb100;
  left.target = 0xb200;
  left.kind = analysis::CodeTargetKind::Jump;
  left.unique = true;
  analysis::CodeTargetFact right = left;
  right.target = 0xb300;

  // Both historical payloads may legitimately remain in the full ledger. A
  // new current observation would reactivate `left` against current `right`,
  // so the existing-payload path must still stage and suppress it.
  analysis::EvidenceStore reactivation;
  CHECK(reactivation.add({ left, evidence_at("old", 40) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  CHECK(reactivation.add({ right, evidence_at("current", 41) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  DeobfEvidenceStoreSink reactivation_sink(reactivation);
  reactivation_sink.set_active_generation(41);
  CHECK(!reactivation_sink.emit_deobf_fact(
      { left, evidence_at("viy.deobf.ida", 41) }));
  CHECK(reactivation_sink.report().contradictions_suppressed == 1);
  CHECK(reactivation.record_count() == 2);
  CHECK(reactivation.observation_count() == 2);
  const analysis::EvidenceRecord *left_record = reactivation.find(left);
  CHECK(left_record != nullptr && left_record->observations.size() == 1);
  CHECK(left_record->observations[0].scope.generation == 40);

  // If both payloads already contradict in the active view (for example after
  // an imported ledger merge), another observation introduces no new conflict
  // and remains useful corroboration.
  analysis::EvidenceStore preexisting;
  CHECK(preexisting.add({ left, evidence_at("import-a", 50) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  CHECK(preexisting.add({ right, evidence_at("import-b", 50) }).disposition
        == analysis::AddDisposition::InsertedRecord);
  DeobfEvidenceStoreSink corroborating_sink(preexisting);
  corroborating_sink.set_active_generation(50);
  CHECK(corroborating_sink.emit_deobf_fact(
      { left, evidence_at("viy.deobf.ida", 50) }));
  CHECK(corroborating_sink.report().contradictions_suppressed == 0);
  CHECK(corroborating_sink.report().added_observations == 1);
  CHECK(preexisting.record_count() == 2);
  CHECK(preexisting.observation_count() == 3);
}

} // anonymous namespace

int main()
{
  test_get_pc();
  test_gap();
  test_entry_predicates();
  test_wrapper();
  test_constants_and_push_ret();
  test_dispatch();
  test_contradiction_gate();
  test_generation_aware_contradiction_gate();
  test_generation_reactivation_and_existing_conflicts();
  std::cout << "deobf analysis tests passed\n";
  return 0;
}
