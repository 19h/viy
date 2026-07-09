/* Convert rax/emulation observations into producer-neutral evidence. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "emu_driver.hpp"
#include "evidence_store.hpp"
#include "program_model.hpp"

namespace viy {

struct ObservedOutcome
{
  EmuOutcome outcome;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

struct EvidenceBridgeStats
{
  size_t inserted_records = 0;
  size_t added_observations = 0;
  size_t duplicates = 0;
  size_t rejected = 0;
};

EvidenceBridgeStats viy_record_emulation_evidence(
    analysis::EvidenceStore &store,
    const ProgramImage &img,
    const FuncRange &function,
    const EmuEvents &events,
    const std::vector<ObservedOutcome> &outcomes);

} // namespace viy
