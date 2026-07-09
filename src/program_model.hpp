/*
 * program_model.hpp — a plain-data snapshot of the analyzed database.
 *
 * All IDA database reads happen in program_model.cpp on the MAIN THREAD and are
 * distilled into POD structures that carry no IDA types. The resulting
 * ProgramImage can then be handed to the (IDA-free) emulation driver. Addresses
 * are plain uint64_t here precisely so this header stays free of <pro.h>; the
 * IDA side casts to/from ea_t (which is uint64 under __EA64__).
 */
#pragma once

#include <cstdint>
#include <vector>

#include "viy_config.hpp"

namespace viy {

// Architectures viy can drive through rax. Others => ViyArch::UNSUPPORTED and
// the sweep silently does nothing.
enum class ViyArch
{
  UNSUPPORTED = 0,
  X86_16,
  X86_32,
  X86_64,
  ARM64,
  ARM32,
};

// One mapped segment's bytes plus an initialized-byte bitmap (1 bit per byte;
// bit set => the byte was loaded, i.e. not .bss). Uninitialized bytes are left
// out of the emulator image and read back as engine zero-fill.
struct SegImage
{
  uint64_t start = 0;
  uint64_t end   = 0;
  uint32_t perm  = 0;   // SEGPERM_* bits (1=exec,2=write,4=read)
  uint8_t  bitness = 0; // 0=16,1=32,2=64
  std::vector<uint8_t> bytes; // size == end-start
  std::vector<uint8_t> mask;  // size == (end-start+7)/8, 1 bit per byte
};

// A function's entry and end, so emulation can restrict recorded refs to sources
// inside the function body (its contiguous primary chunk).
struct FuncRange
{
  uint64_t start = 0;
  uint64_t end   = 0;
};

struct ProgramImage
{
  ViyArch  arch = ViyArch::UNSUPPORTED;
  bool     big_endian = false;
  uint64_t lo = 0;      // min segment start (image lower bound)
  uint64_t hi = 0;      // max segment end   (image upper bound)
  std::vector<SegImage>  segs;
  std::vector<FuncRange> entries; // functions to emulate

  bool byte_loaded(uint64_t ea) const;
};

// Detect the target architecture/endianness from the open database. Returns
// false (out set to UNSUPPORTED) for anything viy does not drive.
bool viy_detect_arch(ViyArch &arch_out, bool &big_endian_out);

// Snapshot segments + function entries into `img`. Main thread only.
void viy_snapshot(ProgramImage &img, const ViyConfig &cfg);

} // namespace viy
