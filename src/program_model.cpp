/*
 * program_model.cpp — read the analyzed program out of the IDA database.
 *
 * Main-thread only (touches the database). Produces a ProgramImage that the
 * IDA-free emulation driver consumes.
 */
#include "program_model.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace viy {

static_assert(static_cast<uint32_t>(ViySegPerm::EXEC) == SEGPERM_EXEC,
              "ViySegPerm must mirror IDA SEGPERM_EXEC");
static_assert(static_cast<uint32_t>(ViySegPerm::WRITE) == SEGPERM_WRITE,
              "ViySegPerm must mirror IDA SEGPERM_WRITE");
static_assert(static_cast<uint32_t>(ViySegPerm::READ) == SEGPERM_READ,
              "ViySegPerm must mirror IDA SEGPERM_READ");

namespace {

bool procname_is(const qstring &name, const char *candidate)
{
  return strieq(name.c_str(), candidate);
}

bool sdk_cortex_m_id(int id)
{
#if defined(PLFM_CORTEXM)
  if ( id == PLFM_CORTEXM )
    return true;
#endif
#if defined(PLFM_CORTEX_M)
  if ( id == PLFM_CORTEX_M )
    return true;
#endif
  (void)id;
  return false;
}

bool sdk_hexagon_id(int id)
{
#if defined(PLFM_QDSP6)
  if ( id == PLFM_QDSP6 )
    return true;
#endif
#if defined(PLFM_HEXAGON)
  if ( id == PLFM_HEXAGON )
    return true;
#endif
  (void)id;
  return false;
}

} // namespace

bool viy_detect_arch(ViyArch &arch_out, bool &big_endian_out)
{
  arch_out = ViyArch::UNSUPPORTED;
  big_endian_out = inf_is_be();

  const int id = PH.id;
  const uint bits = inf_get_app_bitness(); // 16 / 32 / 64
  const bool is64 = inf_is_64bit();

  // Some SDKs expose these as dedicated processor ids. IDA 9.3's bundled
  // Hexagon has the stable short name QDSP6 when no public processor constant
  // is available; recognize that name without embedding a numeric value. Cortex-M
  // normally shares PLFM_ARM today, so only a dedicated id/name is treated as
  // CORTEX_M -- generic all-Thumb ARM firmware is not sufficient proof.
  const qstring procname = inf_get_procname();
  if ( sdk_cortex_m_id(id)
    || procname_is(procname, "Cortex-M")
    || procname_is(procname, "CortexM") )
  {
    arch_out = ViyArch::CORTEX_M;
    return true;
  }
  if ( sdk_hexagon_id(id)
    || procname_is(procname, "QDSP6")
    || procname_is(procname, "Hexagon") )
  {
    arch_out = ViyArch::HEXAGON;
    return true;
  }

  switch ( id )
  {
    case PLFM_386:
      arch_out = bits == 64 ? ViyArch::X86_64
               : bits == 32 ? ViyArch::X86_32
                            : ViyArch::X86_16;
      break;
    case PLFM_ARM:
      arch_out = is64 ? ViyArch::ARM64 : ViyArch::ARM32;
      break;
#if defined(PLFM_RISCV)
    case PLFM_RISCV:
      // The companion rax C ABI currently exposes RV64, not RV32.
      arch_out = bits == 64 ? ViyArch::RISCV64 : ViyArch::UNSUPPORTED;
      break;
#endif
    default:
      arch_out = ViyArch::UNSUPPORTED;
      break;
  }
  return arch_out != ViyArch::UNSUPPORTED;
}

void viy_snapshot(ProgramImage &img, const ViyConfig &cfg)
{
  // Keep prior content generations so an incremental caller can distinguish an
  // unchanged function from one whose bytes or chunk topology changed.
  struct PriorIdentity { uint64_t hash = 0, generation = 0; };
  std::unordered_map<uint64_t, PriorIdentity> prior;
  prior.reserve(img.entries.size());
  for ( const FuncRange &func : img.entries )
    prior[func.start] = PriorIdentity{ func.byte_hash, func.generation };

  if ( img.generation != std::numeric_limits<uint64_t>::max() )
    ++img.generation;

  // Reset so a repeated call does not accumulate duplicate buffers or entries.
  img.segs.clear();
  img.entries.clear();
  img.content_hash = 0;
  img.lo = img.hi = 0;

  viy_detect_arch(img.arch, img.big_endian);

  // ---- segments -----------------------------------------------------------
  const int nsegs = get_segm_qty();
  bool have_bounds = false;
  for ( int i = 0; i < nsegs; ++i )
  {
    segment_t *s = getnseg(i);
    if ( s == nullptr || s->end_ea <= s->start_ea )
      continue;

    SegImage si;
    si.start   = (uint64_t)s->start_ea;
    si.end     = (uint64_t)s->end_ea;
    si.perm    = (uint32_t)s->perm;
    si.bitness = (uint8_t)s->bitness;

    const size_t len = (size_t)(s->end_ea - s->start_ea);
    si.bytes.assign(len, 0);
    si.mask.assign((len + 7) / 8, 0);

    // GMB_READALL: fill what is loaded, mark the rest in `mask`. A -1 result
    // means the user cancelled a (non-existent here) wait box; treat as empty.
    ssize_t got = get_bytes(si.bytes.data(), (ssize_t)len, s->start_ea,
                            GMB_READALL, si.mask.data());
    if ( got < 0 )
      continue;

    if ( !have_bounds )
    {
      img.lo = si.start;
      img.hi = si.end;
      have_bounds = true;
    }
    else
    {
      if ( si.start < img.lo ) img.lo = si.start;
      if ( si.end   > img.hi ) img.hi = si.end;
    }
    img.segs.push_back(std::move(si));
  }
  std::sort(img.segs.begin(), img.segs.end(),
            [](const SegImage &a, const SegImage &b) { return a.start < b.start; });
  img.content_hash = viy_program_content_hash(img);

  // ---- function entries ---------------------------------------------------
  const size_t nfuncs = get_func_qty();
  const size_t cap = cfg.max_funcs != 0 ? (size_t)cfg.max_funcs : nfuncs;
  img.entries.reserve(nfuncs < cap ? nfuncs : cap);
  for ( size_t i = 0; i < nfuncs; ++i )
  {
    if ( img.entries.size() >= cap )
      break;
    func_t *pfn = getn_func(i);
    if ( pfn == nullptr )
      continue;
    // Skip pure library/thunk stubs: their targets are already resolved and
    // emulating them adds noise, not missed refs.
    if ( (pfn->flags & (FUNC_LIB | FUNC_THUNK)) != 0 )
      continue;
    FuncRange func;
    func.start = (uint64_t)pfn->start_ea;
    func.end   = (uint64_t)pfn->end_ea; // compatibility: primary chunk end

    func_tail_iterator_t chunks(pfn);
    for ( bool ok = chunks.main(); ok; ok = chunks.next() )
    {
      const range_t &chunk = chunks.chunk();
      if ( chunk.end_ea > chunk.start_ea )
        func.chunks.push_back(FuncChunk{ (uint64_t)chunk.start_ea, (uint64_t)chunk.end_ea });
    }
    // A valid function always has its entry chunk, but retain a defensive
    // fallback so downstream complete-function membership never becomes empty.
    if ( func.chunks.empty() && func.end > func.start )
      func.chunks.push_back(FuncChunk{ func.start, func.end });

    func.byte_hash = viy_function_byte_hash(img, func);
    const auto old = prior.find(func.start);
    if ( old != prior.end() && old->second.hash == func.byte_hash
      && old->second.generation != 0 )
    {
      func.generation = old->second.generation;
    }
    else
    {
      func.generation = img.generation;
    }
    img.entries.push_back(std::move(func));
  }
  std::sort(img.entries.begin(), img.entries.end(),
            [](const FuncRange &a, const FuncRange &b) { return a.start < b.start; });
}

} // namespace viy
