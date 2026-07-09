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

// Architectures the program model can identify. Individual decoder/emulator
// backends capability-gate this list independently; others are UNSUPPORTED.
enum class ViyArch
{
  UNSUPPORTED = 0,
  X86_16,
  X86_32,
  X86_64,
  ARM64,
  ARM32,
  RISCV64,
  CORTEX_M,
  HEXAGON,
};

// Portable mirrors of IDA's SEGPERM_* bits. Keeping the values here lets the
// IDA-free emulation/analysis side ask permission questions without including
// an SDK header.
enum class ViySegPerm : uint32_t
{
  EXEC  = 1u,
  WRITE = 2u,
  READ  = 4u,
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

  bool contains(uint64_t ea) const;
  bool byte_loaded(uint64_t ea) const;
  bool has_perm(ViySegPerm required) const;
};

// A half-open function chunk [start,end). The first chunk in FuncRange::chunks
// is the entry chunk; subsequent chunks are IDA function tails.
struct FuncChunk
{
  uint64_t start = 0;
  uint64_t end   = 0;

  bool contains(uint64_t ea) const { return ea >= start && ea < end; }
  uint64_t size() const { return end > start ? end - start : 0; }
};

// Version of viy_function_byte_hash(). Persisted consumers should store this
// beside a hash so a future algorithm change cannot be mistaken for new bytes.
constexpr uint32_t VIY_FUNCTION_HASH_VERSION = 1;

// A function entry plus every chunk that IDA assigns to it. `start` and `end`
// deliberately retain their old meanings (entry and end of the PRIMARY chunk)
// so existing callers remain source- and behavior-compatible. New code should
// use contains()/chunks when it needs the complete function.
struct FuncRange
{
  uint64_t start = 0;
  uint64_t end   = 0;
  std::vector<FuncChunk> chunks;

  // Deterministic hash of chunk topology, initialized-byte state, and bytes.
  // The hash is rebase-stable: chunk locations are represented relative to the
  // function entry. See viy_function_byte_hash().
  uint64_t byte_hash = 0;

  // ProgramImage generation in which the current byte_hash was first observed.
  // Re-snapshotting unchanged bytes preserves this value; a content/topology
  // change advances it to the new ProgramImage::generation.
  uint64_t generation = 0;

  bool contains(uint64_t ea) const;
  uint64_t byte_size() const;
};

struct ProgramImage
{
  ViyArch  arch = ViyArch::UNSUPPORTED;
  bool     big_endian = false;
  uint64_t lo = 0;      // min segment start (image lower bound)
  uint64_t hi = 0;      // max segment end   (image upper bound)
  std::vector<SegImage>  segs;
  std::vector<FuncRange> entries; // functions to emulate

  // Rebase-stable identity of segment topology, permissions, initialized-byte
  // state and bytes. Used to invalidate cached emulation when code or any
  // concrete global data visible to a function changes.
  uint64_t content_hash = 0;

  // Monotonic snapshot generation (within this ProgramImage instance).
  uint64_t generation = 0;

  const SegImage *segment_at(uint64_t ea) const;
  bool contains(uint64_t ea) const { return segment_at(ea) != nullptr; }
  bool byte_loaded(uint64_t ea) const;
  bool has_perm(uint64_t ea, ViySegPerm required, bool allow_unknown = false) const;
  bool executable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, ViySegPerm::EXEC, allow_unknown);
  }
  bool writable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, ViySegPerm::WRITE, allow_unknown);
  }
  bool readable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, ViySegPerm::READ, allow_unknown);
  }

  const FuncRange *function_at(uint64_t ea) const;
};

// Stable, IDA-independent identity for a function's current bytes in `img`.
// It includes every chunk, holes/uninitialized bytes, and relative chunk
// topology, but not absolute addresses (so rebasing does not change the hash).
uint64_t viy_function_byte_hash(const ProgramImage &img, const FuncRange &func);
uint64_t viy_program_content_hash(const ProgramImage &img);

// Detect the target architecture/endianness from the open database. Returns
// false (out set to UNSUPPORTED) for anything viy cannot identify safely.
bool viy_detect_arch(ViyArch &arch_out, bool &big_endian_out);

// Snapshot segments + function entries into `img`. Main thread only.
void viy_snapshot(ProgramImage &img, const ViyConfig &cfg);

} // namespace viy
