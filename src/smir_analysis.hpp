/*
 * Producer-neutral consumer for rax 1.3 stateless SMIR effects.
 *
 * This layer has no IDA SDK dependency. It reads bytes only from ProgramImage,
 * negotiates the caller-owned C-ABI effect array, and can translate effects
 * that are genuine static facts into EvidenceStore records. Integration should
 * call viy_analyze_instruction_effects() from the existing decoder-audit walk
 * (where IDA instruction heads/modes are already known), then call
 * viy_record_smir_analysis().
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "evidence_store.hpp"
#include "program_model.hpp"
#include "rax_loader.hpp"

namespace viy {

struct SmirInstructionAnalysis
{
  uint64_t instruction = 0;
  int arch = 0;
  uint32_t mode = 0;
  rax_analysis summary{};
  std::vector<rax_analysis_effect> effects;
};

struct SmirAnalysisStats
{
  size_t instructions_analyzed = 0;
  size_t unsupported = 0;
  size_t partial = 0;
  size_t register_constant_facts = 0;
  size_t memory_access_facts = 0;
  size_t code_target_facts = 0;
  size_t observations_inserted = 0;
  size_t observations_deduplicated = 0;
  size_t observations_rejected = 0;
};

// Analyze one address from the immutable image. `mode_override` is used when
// nonzero; otherwise the mode is derived conservatively from ProgramImage.
// Returns false for absent capability, unmapped/unloaded bytes, bad ABI output,
// or a hard rax error. Unsupported-but-valid decode is a successful result with
// RAX_ANALYSIS_UNSUPPORTED in out.summary.flags.
bool viy_analyze_instruction_effects(const RaxApi *api,
                                     const ProgramImage &image,
                                     uint64_t instruction,
                                     uint32_t mode_override,
                                     SmirInstructionAnalysis &out);

// Store only facts the stateless lift proves directly: encoded control targets,
// resolved absolute memory accesses, and <=64-bit constant register results.
// Base/index expressions stay in SmirInstructionAnalysis for future symbolic
// consumers rather than being weakened into guessed absolute addresses.
SmirAnalysisStats viy_record_smir_analysis(const SmirInstructionAnalysis &input,
                                           const FuncRange &function,
                                           analysis::EvidenceStore &store);

} // namespace viy

