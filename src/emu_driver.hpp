/*
 * emu_driver.hpp — drive rax to emulate the analyzed image and record the
 * control-flow edges and data accesses IDA's static pass could not resolve.
 *
 * This module is PURE rax: it includes no IDA headers and never touches the
 * database, so it is safe to run off the main thread against a pre-copied
 * ProgramImage. It produces raw addresses; classification into crefs/drefs and
 * the add-only-if-missing diff live in ref_discovery (which is on the DB side).
 */
#pragma once

#include <cstdint>
#include <vector>

#include "rax_loader.hpp"
#include "program_model.hpp"
#include "viy_config.hpp"

struct rax_engine; // opaque

namespace viy {

// A taken control transfer prev->to observed during emulation (to != the static
// fall-through of prev). `from` is the transferring instruction.
struct ExecEdge
{
  uint64_t from = 0;
  uint64_t to   = 0;
};

// A data memory access observed during emulation, attributed to the executing
// instruction `from`. `kind` is RAX_MEM_READ / RAX_MEM_WRITE.
struct DataAcc
{
  uint64_t from = 0;
  uint64_t addr = 0;
  uint32_t size = 0;
  int      kind = 0;
};

struct EmuEvents
{
  std::vector<ExecEdge> edges;
  std::vector<DataAcc>  data;
};

class EmuDriver
{
public:
  EmuDriver(const RaxApi *api, const ProgramImage &img);
  ~EmuDriver();

  EmuDriver(const EmuDriver &) = delete;
  EmuDriver &operator=(const EmuDriver &) = delete;

  // True iff the engine opened and the image mapped: emulation is possible.
  bool ok() const { return engine_ != nullptr; }
  // True iff discovery can run: the engine opened, the backend supports
  // single-stepping (required for code hooks, hence edge discovery), AND a clean
  // baseline was captured (required for correct per-run isolation). When false,
  // emulate_from() is a no-op.
  bool can_discover() const { return ok() && stepping_ && baseline_ok_; }

  // Emulate one function (its entry .. func_end) under the caps in `cfg`,
  // appending discovered edges/data to `out`. Only edges/accesses whose source
  // instruction lies within [entry, func_end) are recorded, so callee bodies
  // executed under this function's fabricated state do not contribute noise —
  // each function is mined from its own entry. Bounded by instruction count and
  // wall-clock timeout; faults are contained. Returns true if emulation ran.
  bool emulate_from(uint64_t entry, uint64_t func_end, const ViyConfig &cfg, EmuEvents &out);

private:
  bool map_image();
  bool map_stack();
  void load_image_bytes();
  void save_baseline();
  void restore_state();

  const RaxApi     *api_ = nullptr;
  const ProgramImage &img_;
  rax_engine       *engine_ = nullptr;
  bool              stepping_ = false;
  bool              mem_hooks_ok_ = false;

  // Per-arch execution parameters resolved in the constructor.
  int      sp_reg_ = -1;   // stack-pointer register id
  int      fp_reg_ = -1;   // frame-pointer register id (-1 if none)
  int      lr_reg_ = -1;   // link register id (-1 => return address is on stack)
  uint64_t stack_base_ = 0;
  uint64_t stack_size_ = 0;
  uint64_t sentinel_ = 0;  // "returned out of the function" stop address

  std::vector<uint8_t> baseline_; // rax context snapshot (image+regs) for reuse
  bool baseline_ok_ = false;
};

} // namespace viy
