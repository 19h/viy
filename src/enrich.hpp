/*
 * enrich.hpp — turn rax's concrete values into IDA annotations.
 *
 * Beyond cross-references, an emulation run knows the actual register and memory
 * values at every instruction — something static analysis cannot recover. This
 * pass mines that to (1) materialize in-image pointers loaded from memory
 * (vtables, function-pointer tables, relocated/computed pointers) as typed
 * offset data, (2) type undefined globals by the observed access size, and
 * (3) drop repeatable comments naming what rax resolved.
 *
 * Everything here is ADDITIVE and heavily guarded — it only touches undefined
 * bytes inside the image, never overwrites an existing item, type, or comment,
 * and only ever adds. Main thread only.
 */
#pragma once

#include <cstddef>

#include "emu_driver.hpp" // EmuEvents
#include "viy_config.hpp"

namespace viy {

struct EnrichStats
{
  size_t ptr_refs = 0; // in-image pointers materialized (offset + dref)
  size_t typed    = 0; // undefined globals given a data type
  size_t comments = 0; // annotations added
};

// Apply the value-derived enrichments implied by `ev`. Main thread only.
EnrichStats viy_enrich(const EmuEvents &ev, const ViyConfig &cfg);

} // namespace viy
