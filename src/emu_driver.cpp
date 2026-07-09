/*
 * emu_driver.cpp — the rax emulation core.
 *
 * Strategy: mirror the analyzed image into guest memory once, then emulate each
 * function from its entry with a plausible stack whose top holds a sentinel
 * return address. A whole-range code hook records every executed PC (so any
 * taken branch whose target is not the static fall-through becomes a candidate
 * edge — this is how indirect calls/jumps and jump-table targets surface). A
 * memory hook records data reads/writes (computed data references). An invalid
 * hook absorbs faults so a bad path stops cleanly instead of crashing or
 * hanging; an instruction-count and wall-clock cap bound every run.
 *
 * Per-run isolation uses rax context snapshots: the clean image+stack+registers
 * are captured once, and restored before each run so one function's stores can't
 * poison another's reads.
 */
#include "emu_driver.hpp"

#include <algorithm>
#include <cstring>

namespace viy {

namespace {

constexpr uint64_t kPage      = 0x1000;
constexpr uint64_t kStackSize = 0x100000;           // 1 MiB scratch stack
constexpr uint64_t kMaxCtx    = 512ull * 1024 * 1024; // cap snapshot buffer size

inline uint64_t page_down(uint64_t x) { return x & ~(kPage - 1); }
inline uint64_t page_up(uint64_t x)   { return (x + kPage - 1) & ~(kPage - 1); }

// The stable context handed to every hook via the rax `user` pointer.
struct HookCtx
{
  EmuEvents *out = nullptr;
  uint64_t   lo = 0, hi = 0;      // image bounds; targets outside are ignored
  uint64_t   flo = 0, fhi = 0;    // current function bounds; only in-function sources are trusted
  uint64_t   prev_pc = 0, last_pc = 0;
  uint32_t   prev_size = 0;
  bool       has_prev = false;
  size_t     edge_cap = 0, data_cap = 0;
};

void code_tr(rax_engine *, uint64_t addr, uint32_t size, void *user)
{
  HookCtx *c = static_cast<HookCtx *>(user);
  if ( c->has_prev )
  {
    const uint64_t fallthrough = c->prev_pc + c->prev_size;
    // Record a taken branch only when its SOURCE is inside the function being
    // emulated (prev_pc in [flo,fhi)) and its TARGET is inside the image. This
    // keeps callee bodies (executed under this function's fabricated state) from
    // contributing edges — each function is mined from its own entry.
    if ( addr != fallthrough
      && addr >= c->lo && addr < c->hi
      && c->prev_pc >= c->flo && c->prev_pc < c->fhi
      && c->out->edges.size() < c->edge_cap )
    {
      c->out->edges.push_back(ExecEdge{ c->prev_pc, addr });
    }
  }
  c->prev_pc = addr;
  c->prev_size = size;
  c->has_prev = true;
  c->last_pc = addr;
}

void mem_tr(rax_engine *, int kind, uint64_t addr, uint32_t size, uint64_t value, void *user)
{
  HookCtx *c = static_cast<HookCtx *>(user);
  if ( kind == RAX_MEM_FETCH )
    return; // instruction fetch is control flow, not a data reference
  // Attribute to the executing instruction (last_pc, set by the code hook at
  // instruction entry; rax dispatches an access at the boundary of the
  // instruction that made it, before the next instruction's code hook). Only
  // trust accesses whose source is inside the function being emulated.
  if ( addr >= c->lo && addr < c->hi
    && c->last_pc >= c->flo && c->last_pc < c->fhi
    && c->out->data.size() < c->data_cap )
  {
    c->out->data.push_back(DataAcc{ c->last_pc, addr, value, size, kind });
  }
}

int inv_tr(rax_engine *, uint64_t, void *)
{
  return 0; // do not handle the fault: stop the run cleanly
}

// Fill the rax arch/mode and the register ids for a supported ViyArch.
// Returns false for architectures viy does not drive.
bool arch_params(ViyArch a, bool big_endian,
                 int &rax_arch, uint32_t &mode,
                 int &sp_reg, int &fp_reg, int &lr_reg, bool &is64)
{
  sp_reg = fp_reg = lr_reg = -1;
  switch ( a )
  {
    // X86_16 (segmented real mode) is intentionally not driven: linear IDA
    // addresses don't map to seg:off state and the stack model differs. It
    // falls through to `return false`, so the sweep is a clean no-op there.
    case ViyArch::X86_32:
      rax_arch = RAX_ARCH_X86; mode = RAX_MODE_32;
      sp_reg = RAX_X86_REG_RSP; fp_reg = RAX_X86_REG_RBP; is64 = false; return true;
    case ViyArch::X86_64:
      rax_arch = RAX_ARCH_X86; mode = RAX_MODE_64;
      sp_reg = RAX_X86_REG_RSP; fp_reg = RAX_X86_REG_RBP; is64 = true; return true;
    case ViyArch::ARM64:
      rax_arch = RAX_ARCH_ARM64;
      mode = big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN;
      sp_reg = RAX_ARM64_REG_SP; lr_reg = RAX_ARM64_X(30); is64 = true; return true;
    case ViyArch::ARM32:
      rax_arch = RAX_ARCH_ARM;
      mode = RAX_MODE_ARM | (big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN);
      sp_reg = RAX_ARM_REG_SP; lr_reg = RAX_REG_LR; is64 = false; return true;
    default:
      return false;
  }
}

} // namespace

EmuDriver::EmuDriver(const RaxApi *api, const ProgramImage &img)
  : api_(api), img_(img)
{
  int rax_arch = 0, sp = -1, fp = -1, lr = -1;
  uint32_t mode = 0;
  bool is64 = false;
  if ( !arch_params(img_.arch, img_.big_endian, rax_arch, mode, sp, fp, lr, is64) )
    return;
  sp_reg_ = sp; fp_reg_ = fp; lr_reg_ = lr;

  // Choose a scratch stack region that does not intersect the image. This region
  // doubles as the engine's initial (default) mapping, so it never collides with
  // the image maps below.
  static const uint64_t cand64[] = { 0x00007ffd00000000ull, 0x0000600000000000ull, 0x0000000120000000ull };
  static const uint64_t cand32[] = { 0x70000000ull, 0x50000000ull, 0x10000000ull };
  const uint64_t *cands = is64 ? cand64 : cand32;
  const size_t ncand = is64 ? 3 : 3;
  stack_size_ = kStackSize;
  bool chosen = false;
  for ( size_t i = 0; i < ncand; ++i )
  {
    const uint64_t b = cands[i];
    const uint64_t e = b + stack_size_;
    const bool intersects = img_.hi > img_.lo && b < img_.hi && img_.lo < e;
    if ( !intersects )
    {
      stack_base_ = b;
      chosen = true;
      break;
    }
  }
  if ( !chosen )
    return; // no scratch-stack region clear of the image; leave the engine closed (no-op)
  sentinel_ = stack_base_ + kPage;

  rax_engine_config cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.size      = sizeof(cfg);
  cfg.arch      = rax_arch;
  cfg.mode      = mode;
  cfg.backend   = RAX_BACKEND_EMULATOR;
  cfg.mem_base  = stack_base_;
  cfg.mem_size  = stack_size_;
  cfg.mem_perms = RAX_PROT_ALL;
  cfg.flags     = 0;

  if ( api_->engine_open_config(&cfg, &engine_) != RAX_OK || engine_ == nullptr )
  {
    engine_ = nullptr;
    return;
  }

  stepping_ = api_->engine_supports_stepping(engine_) != 0;

  if ( !map_image() )
  {
    api_->engine_close(engine_);
    engine_ = nullptr;
    return;
  }
  map_stack();

  // Probe whether the backend records per-access memory (x86-64 today). If not,
  // drefs are simply skipped; crefs still work wherever code hooks fire.
  uint32_t probe_id = 0;
  if ( api_->hook_add_mem(engine_, RAX_HOOK_MEM_READ, 1, 0, mem_tr, nullptr, &probe_id) == RAX_OK )
  {
    mem_hooks_ok_ = true;
    api_->hook_del(engine_, probe_id);
  }

  save_baseline();
}

EmuDriver::~EmuDriver()
{
  if ( engine_ != nullptr )
    api_->engine_close(engine_);
  engine_ = nullptr;
}

bool EmuDriver::map_image()
{
  // Merge segments into page-aligned intervals so adjacent/overlapping segments
  // do not cause overlapping mem_map calls.
  struct IV { uint64_t base, end; };
  std::vector<IV> ivs;
  ivs.reserve(img_.segs.size());
  for ( const SegImage &s : img_.segs )
  {
    if ( s.end <= s.start )
      continue;
    ivs.push_back(IV{ page_down(s.start), page_up(s.end) });
  }
  std::sort(ivs.begin(), ivs.end(), [](const IV &a, const IV &b) { return a.base < b.base; });

  std::vector<IV> merged;
  for ( const IV &iv : ivs )
  {
    if ( !merged.empty() && iv.base <= merged.back().end )
    {
      if ( iv.end > merged.back().end )
        merged.back().end = iv.end;
    }
    else
    {
      merged.push_back(iv);
    }
  }

  for ( const IV &iv : merged )
  {
    const uint64_t len = iv.end - iv.base;
    int st = api_->mem_map(engine_, iv.base, len, RAX_PROT_ALL);
    if ( st != RAX_OK )
    {
      // Possibly already mapped (e.g. the default stack region if a candidate
      // overlapped): make sure it is at least accessible, otherwise give up.
      if ( api_->mem_protect(engine_, iv.base, len, RAX_PROT_ALL) != RAX_OK )
        return false;
    }
  }

  load_image_bytes();
  return true;
}

void EmuDriver::load_image_bytes()
{
  // Write each segment's initialized bytes; leave holes (.bss) as zero-fill.
  // Used once at map time; per-run restoration is done via the context snapshot
  // (see restore_state / save_baseline), which resets memory AND registers.
  for ( const SegImage &s : img_.segs )
  {
    const size_t len = s.bytes.size();
    size_t i = 0;
    while ( i < len )
    {
      while ( i < len && (s.mask[i / 8] & (1u << (i & 7))) == 0 )
        ++i; // skip an uninitialized run
      if ( i >= len )
        break;
      size_t j = i;
      while ( j < len && (s.mask[j / 8] & (1u << (j & 7))) != 0 )
        ++j;
      api_->mem_write(engine_, s.start + i, s.bytes.data() + i, j - i);
      i = j;
    }
  }
}

bool EmuDriver::map_stack()
{
  // The stack is the engine's default region (mem_base/mem_size at open); just
  // make sure it is fully accessible.
  return api_->mem_protect(engine_, stack_base_, stack_size_, RAX_PROT_ALL) == RAX_OK;
}

void EmuDriver::save_baseline()
{
  baseline_ok_ = false;
  baseline_.clear();
  if ( api_->context_save == nullptr )
    return;
  size_t len = 0;
  if ( api_->context_save(engine_, nullptr, 0, &len) != RAX_OK || len == 0 || len > kMaxCtx )
    return;
  try
  {
    baseline_.resize(len);
  }
  catch ( ... ) // bad_alloc on a very large image: no baseline => no discovery
  {
    baseline_.clear();
    return;
  }
  if ( api_->context_save(engine_, baseline_.data(), baseline_.size(), &len) != RAX_OK )
  {
    baseline_.clear();
    return;
  }
  baseline_.resize(len);
  baseline_ok_ = true;
}

void EmuDriver::restore_state()
{
  // Restore the clean baseline (memory + registers) before each run so per-run
  // isolation holds: one function's stores and leftover register values can't
  // leak into the next. A captured baseline is REQUIRED for discovery (see
  // can_discover), so this always restores.
  api_->context_restore(engine_, baseline_.data(), baseline_.size());
}

bool EmuDriver::emulate_from(uint64_t entry, uint64_t func_end, const ViyConfig &cfg, EmuEvents &out)
{
  if ( !can_discover() )
    return false;

  restore_state();

  const bool is64 = img_.arch == ViyArch::X86_64 || img_.arch == ViyArch::ARM64;
  const uint64_t align = is64 ? 0xFull : 0x3ull;
  uint64_t sp = (stack_base_ + stack_size_ - 0x400) & ~align;
  if ( img_.arch == ViyArch::X86_64 )
    sp |= 0x8; // x86-64 ABI: rsp%16 == 8 at entry (after the call pushed retaddr)

  if ( sp_reg_ >= 0 )
    api_->reg_write_u64(engine_, sp_reg_, sp);
  if ( fp_reg_ >= 0 )
    api_->reg_write_u64(engine_, fp_reg_, sp);

  if ( lr_reg_ >= 0 )
  {
    // Link-register architectures (ARM): the return address lives in LR.
    api_->reg_write_u64(engine_, lr_reg_, sentinel_);
  }
  else
  {
    // Stack-return architectures (x86): place the sentinel at [sp].
    const size_t ptr = is64 ? 8 : 4;
    uint8_t buf[8] = { 0 };
    uint64_t s = sentinel_;
    for ( size_t k = 0; k < ptr; ++k )
      buf[k] = (uint8_t)((s >> (8 * k)) & 0xFF);
    api_->mem_write(engine_, sp, buf, ptr);
  }

  HookCtx ctx;
  ctx.out = &out;
  ctx.lo = img_.lo;
  ctx.hi = img_.hi;
  ctx.flo = entry;
  ctx.fhi = func_end > entry ? func_end : img_.hi;
  ctx.edge_cap = (size_t)cfg.max_insns;
  ctx.data_cap = (size_t)cfg.max_insns;

  uint32_t code_id = 0, mem_id = 0, inv_id = 0;
  bool code_ok = api_->hook_add_code(engine_, 1, 0, code_tr, &ctx, &code_id) == RAX_OK;
  bool mem_ok = false;
  if ( cfg.want_drefs && mem_hooks_ok_ )
  {
    mem_ok = api_->hook_add_mem(engine_,
                                RAX_HOOK_MEM_READ | RAX_HOOK_MEM_WRITE,
                                1, 0, mem_tr, &ctx, &mem_id) == RAX_OK;
  }
  bool inv_ok = api_->hook_add_invalid(engine_, inv_tr, &ctx, &inv_id) == RAX_OK;

  if ( code_ok )
  {
    const uint64_t timeout_us = cfg.timeout_ms * 1000ull;
    api_->emu_start(engine_, entry, sentinel_, timeout_us, cfg.max_insns);
  }

  if ( code_ok ) api_->hook_del(engine_, code_id);
  if ( mem_ok )  api_->hook_del(engine_, mem_id);
  if ( inv_ok )  api_->hook_del(engine_, inv_id);

  return code_ok;
}

} // namespace viy
